package com.sparrowwallet.lark;

import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTOutput;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.lark.trezor.PassphraseUI;
import com.sparrowwallet.lark.trezor.TrezorDevice;
import com.sparrowwallet.lark.trezor.TrezorModel;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageBitcoin;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageCommon;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageManagement;
import org.usb4java.Device;
import org.usb4java.DeviceDescriptor;
import org.usb4java.LibUsb;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.IntStream;

public class TrezorClient extends HardwareClient {
    public static final List<DeviceId> TREZOR_DEVICE_IDS = List.of(new DeviceId(0x534C, 0x0001),
            new DeviceId(0x1209, 0x53C1), new DeviceId(0x1209, 0x53C0));

    private static final String PATH_PREFIX = "webusb";

    public static final String PIN_MATRIX_DESCRIPTION = """
        Use the numeric keypad to describe number positions. The layout is:
            7 8 9
            4 5 6
            1 2 3
        """.strip();

    private final List<TrezorMessageBitcoin.InputScriptType> ECDSA_SCRIPT_TYPES = List.of(
            TrezorMessageBitcoin.InputScriptType.SPENDADDRESS,
            TrezorMessageBitcoin.InputScriptType.SPENDMULTISIG,
            TrezorMessageBitcoin.InputScriptType.SPENDWITNESS,
            TrezorMessageBitcoin.InputScriptType.SPENDP2SHWITNESS
    );

    private final List<TrezorMessageBitcoin.InputScriptType> SCHNORR_SCRIPT_TYPES = List.of(
            TrezorMessageBitcoin.InputScriptType.SPENDTAPROOT
    );

    private final Device device;
    private final int busNumber;
    private final ByteBuffer portNumbers = ByteBuffer.allocateDirect(7);
    private String passphrase = "";

    private WalletModel model;
    private TrezorModel trezorModel;
    private String label;
    private Boolean needsPinSent;
    private Boolean needsPassphraseSent;
    private String masterFingerprint;
    private final List<String> warnings = new ArrayList<>();

    public TrezorClient(Device device, DeviceDescriptor deviceDescriptor) throws DeviceException {
        this(TREZOR_DEVICE_IDS, device, deviceDescriptor, null);
    }

    protected TrezorClient(List<DeviceId> deviceIds, Device device, DeviceDescriptor deviceDescriptor, TrezorModel trezorModel) throws DeviceException {
        if(deviceIds.stream().anyMatch(deviceId -> deviceId.matches(deviceDescriptor))) {
            this.device = device;
            this.busNumber = LibUsb.getBusNumber(device);
            LibUsb.getPortNumbers(device, portNumbers);
            this.trezorModel = trezorModel;
        } else {
            throw new DeviceException("Not a " + getHardwareType().getDisplayName());
        }
    }

    private void prepareDevice(TrezorDevice trezorDevice) throws DeviceException {
        trezorDevice.refreshFeatures();
        if(trezorDevice.getModel() == TrezorModel.T1B1 || trezorDevice.getModel() == TrezorModel.KEEPKEY || trezorDevice.getModel() == TrezorModel.ONEKEY_CLASSIC_1S) {
            trezorDevice.initDevice();
        } else {
            try {
                trezorDevice.ensureUnlocked();
            } catch(DeviceException e) {
                trezorDevice.initDevice();
            }
        }

        this.trezorModel = trezorDevice.getModel();
        this.model = trezorDevice.getModel().getWalletModel();
        this.label = trezorDevice.getFeatures().getLabel();
        this.needsPinSent = trezorDevice.getFeatures().getPinProtection() && !trezorDevice.getFeatures().getUnlocked();
        if(trezorDevice.getModel().equals(TrezorModel.T1B1) || trezorDevice.getModel().equals(TrezorModel.ONEKEY_CLASSIC_1S)) {
            this.needsPassphraseSent = trezorDevice.getFeatures().getPassphraseProtection();
        } else {
            this.needsPassphraseSent = false;
        }
        if(needsPinSent) {
            throw new DeviceNotReadyException(getHardwareType().getDisplayName() + " is locked. Unlock by using 'promptpin' and then 'sendpin'.");
        }
        if(needsPassphraseSent && passphrase == null) {
            setError("Passphrase needs to be specified before fingerprint information can be retrieved");
            return;
        }
        if(trezorDevice.getFeatures().getInitialized()) {
            initializeMasterFingerprint(trezorDevice);
            this.needsPassphraseSent = false; //Passphrase is always needed for the above to have worked, so it's already sent
        } else {
            throw new DeviceNotReadyException(getHardwareType().getDisplayName() + " is not initialized.");
        }
        if(trezorDevice.isOutdatedFirmware()) {
            this.warnings.add("Trezor firmware is outdated, please update to the latest version");
        }
    }

    private void checkUnlocked(TrezorDevice trezorDevice) throws DeviceException {
        prepareDevice(trezorDevice);
        if(trezorDevice.getFeatures().getCapabilitiesList().stream().anyMatch(TrezorMessageManagement.Features.Capability.Capability_PassphraseEntry::equals)
                && trezorDevice.getUI() instanceof PassphraseUI) {
            trezorDevice.getUI().disallowPassphrase();
        }
        if(trezorDevice.getFeatures().getPinProtection() && !trezorDevice.getFeatures().getUnlocked()) {
            throw new DeviceNotReadyException(getHardwareType().getDisplayName() + " is locked. Unlock by using 'promptpin' and then 'sendpin'.'");
        }
        if(trezorDevice.getFeatures().getPassphraseProtection() && passphrase == null) {
            throw new DeviceException("Passphrase protection is enabled, passphrase must be provided");
        }
    }

    private String getMasterFingerprint(TrezorDevice trezorDevice) throws DeviceException {
        TrezorMessageBitcoin.PublicKey masterKey = trezorDevice.getPublicNode(Network.MAINNET, List.of(ChildNumber.ZERO_HARDENED));
        if(masterKey.getRootFingerprint() != 0) {
            return String.format("%08x", masterKey.getRootFingerprint());
        }
        return Utils.bytesToHex(Arrays.copyOfRange(Base58.decode(masterKey.getXpub()), 5, 9));
    }

    @Override
    void initializeMasterFingerprint() throws DeviceException {
        try(TrezorDevice trezorDevice = new TrezorDevice(device, new PassphraseUI(passphrase), trezorModel)) {
            prepareDevice(trezorDevice);
        }
    }

    private void initializeMasterFingerprint(TrezorDevice trezorDevice) throws DeviceException {
        this.masterFingerprint = getMasterFingerprint(trezorDevice);
    }

    @Override
    ExtendedKey getPubKeyAtPath(String path) throws DeviceException {
        try(TrezorDevice trezorDevice = new TrezorDevice(device, new PassphraseUI(passphrase), trezorModel)) {
            checkUnlocked(trezorDevice);
            TrezorMessageBitcoin.PublicKey publicKey = trezorDevice.getPublicNode(Network.get(), KeyDerivation.parsePath(path));
            return ExtendedKey.fromDescriptor(publicKey.getXpub());
        }
    }

    /**
     * Sign a transaction with the Trezor. There are some limitations to what transactions can be signed.
     * - Multisig inputs are limited to at most n-of-15 multisigs. This is a firmware limitation.
     * - Transactions with arbitrary input scripts (scriptPubKey, redeemScript, or witnessScript) and arbitrary output scripts cannot be signed. This is a firmware limitation.
     * - Send-to-self transactions will result in no prompt for outputs as all outputs will be detected as change.
     * - Transactions containing Taproot inputs cannot have external inputs.
     *
     * @param psbt the PSBT to be signed
     * @return the signed PSBT
     * @throws DeviceException on an error
     */
    @Override
    PSBT signTransaction(PSBT psbt) throws DeviceException {
        try(TrezorDevice trezorDevice = new TrezorDevice(device, new PassphraseUI(passphrase), trezorModel)) {
            checkUnlocked(trezorDevice);

            int passes = 1;
            int p = 0;

            while(p < passes) {
                List<TrezorMessageBitcoin.TxInput> inputs = new ArrayList<>();
                List<Integer> toIgnore = new ArrayList<>();

                for(int inputIndex = 0; inputIndex < psbt.getPsbtInputs().size(); inputIndex++) {
                    PSBTInput psbtInput = psbt.getPsbtInputs().get(inputIndex);

                    TrezorMessageBitcoin.TxInput.Builder txInput = TrezorMessageBitcoin.TxInput.newBuilder()
                            .setPrevHash(ByteString.copyFrom(Utils.reverseBytes(serUInt256(psbtInput.getInput().getOutpoint().getHash().toBigInteger()))))
                            .setPrevIndex((int)psbtInput.getInput().getOutpoint().getIndex())
                            .setSequence((int)psbtInput.getInput().getSequenceNumber());

                    //Determine spend type
                    TransactionOutput utxo = psbtInput.getUtxo();
                    if(utxo == null) {
                        continue;
                    }
                    Script script = utxo.getScript();

                    //Check if P2SH
                    boolean p2sh = false;
                    if(ScriptType.P2SH.isScriptType(script)) {
                        //Lookup redeem script
                        if(psbtInput.getRedeemScript() == null) {
                            continue;
                        }
                        script = psbtInput.getRedeemScript();
                        p2sh = true;
                    }

                    //Check if segwit
                    Script inputScript = script;
                    Optional<ScriptType> optWitnessType = isWitness(inputScript);
                    if(optWitnessType.isPresent()) {
                        ScriptType witnessType = optWitnessType.get();
                        if(witnessType.equals(ScriptType.P2WPKH) || witnessType.equals(ScriptType.P2WSH)) {
                            if(p2sh) {
                                txInput.setScriptType(TrezorMessageBitcoin.InputScriptType.SPENDP2SHWITNESS);
                            } else {
                                txInput.setScriptType(TrezorMessageBitcoin.InputScriptType.SPENDWITNESS);
                            }
                        } else if(witnessType.equals(ScriptType.P2TR)) {
                            txInput.setScriptType(TrezorMessageBitcoin.InputScriptType.SPENDTAPROOT);
                        }
                    } else {
                        txInput.setScriptType(TrezorMessageBitcoin.InputScriptType.SPENDADDRESS);
                    }
                    txInput.setAmount(utxo.getValue());

                    //Check if P2WSH
                    boolean p2wsh = false;
                    if(ScriptType.P2WSH.isScriptType(script)) {
                        //Look up witnessScript
                        if(psbtInput.getWitnessScript() == null) {
                            continue;
                        }
                        script = psbtInput.getWitnessScript();
                        p2wsh = true;
                    }

                    //Check for multisig
                    Optional<TrezorMessageBitcoin.MultisigRedeemScriptType> optMultisigRedeemScriptType = getMultisig(script, psbt.getExtendedPublicKeys(), psbtInput.getDerivedPublicKeys());
                    if(optMultisigRedeemScriptType.isPresent()) {
                        txInput.setMultisig(optMultisigRedeemScriptType.get());
                        if(optWitnessType.isEmpty()) {
                            if(ScriptType.P2SH.isScriptType(utxo.getScript())) {
                                txInput.setScriptType(TrezorMessageBitcoin.InputScriptType.SPENDMULTISIG);
                            } else {
                                //Cannot sign bare multisig, ignore it
                                if(!trezorDevice.supportsExternal()) {
                                    throw new DeviceException("Cannot sign bare multisig inputs");
                                }
                                ignoreInput(inputs, toIgnore, inputIndex, txInput);
                                continue;
                            }
                        }
                    } else if(optWitnessType.isEmpty() && !ScriptType.P2PKH.isScriptType(script)) {
                        //Cannot sign unknown spk, ignore it
                        if(!trezorDevice.supportsExternal()) {
                            throw new DeviceException("Cannot sign unknown scripts");
                        }
                        ignoreInput(inputs, toIgnore, inputIndex, txInput);
                        continue;
                    } else if(optWitnessType.isPresent() && p2wsh) {
                        //Cannot sign unknown witness script, ignore it
                        if(!trezorDevice.supportsExternal()) {
                            throw new DeviceException("Cannot sign unknown witness versionss");
                        }
                        ignoreInput(inputs, toIgnore, inputIndex, txInput);
                        continue;
                    }

                    //Find key to sign with
                    boolean found = false; //Whether we have found a key to sign with
                    boolean foundInSigs = false; //Whether we have found one of our keys in the signatures
                    int ourKeys = 0;
                    List<ChildNumber> pathLastOurs = null; //The path of the last key that is ours. We will use this if we need to ignore this input because it is already signed.
                    if(ECDSA_SCRIPT_TYPES.contains(txInput.getScriptType())) {
                        for(ECKey key : psbtInput.getDerivedPublicKeys().keySet()) {
                            KeyDerivation keypath = psbtInput.getDerivedPublicKeys().get(key);
                            if(keypath.getMasterFingerprint().equals(masterFingerprint)) {
                                pathLastOurs = keypath.getDerivation();
                                if(psbtInput.getPartialSignatures().containsKey(key)) { //This key already has a signature
                                    foundInSigs = true;
                                    continue;
                                }
                                if(!found) { //This key does not have a signature, and we don't have a key to sign with yet
                                    txInput.addAllAddressN(keypath.getDerivation().stream().map(ChildNumber::i).toList());
                                    found = true;
                                }
                                ourKeys++;
                            }
                        }
                    } else if(SCHNORR_SCRIPT_TYPES.contains(txInput.getScriptType())) {
                        foundInSigs = psbtInput.getTapKeyPathSignature() != null;
                        for(ECKey key : psbtInput.getTapDerivedPublicKeys().keySet()) {
                            Map<KeyDerivation, List<Sha256Hash>> keypath = psbtInput.getTapDerivedPublicKeys().get(key);
                            for(KeyDerivation keypathKey : keypath.keySet()) {
                                //Note script path signing is not currently supported
                                if(key.equals(psbtInput.getTapInternalKey()) && keypathKey.getMasterFingerprint().equals(masterFingerprint)) {
                                    pathLastOurs = keypathKey.getDerivation();
                                    txInput.addAllAddressN(keypathKey.getDerivation().stream().map(ChildNumber::i).toList());
                                    found = true;
                                    ourKeys++;
                                    break;
                                }
                            }
                        }
                    }

                    //Determine if we need to do more passes to sign everything
                    if(ourKeys > passes) {
                        passes = ourKeys;
                    }

                    if(!found && !foundInSigs) {
                        //This input is not one of ours
                        if(!trezorDevice.supportsExternal()) {
                            throw new DeviceException("Cannot sign external inputs");
                        }
                        ignoreInput(inputs, toIgnore, inputIndex, txInput);
                        continue;
                    } else if(!found && foundInSigs) {
                        //All of our keys are in partial_sigs, pick the first key that is ours, sign with it,
                        //and ignore whatever signature is produced for this input
                        if(pathLastOurs == null) {
                            throw new IllegalStateException("Cannot determine path for input " + inputIndex);
                        }
                        txInput.addAllAddressN(pathLastOurs.stream().map(ChildNumber::i).toList());
                        toIgnore.add(inputIndex);
                    }

                    inputs.add(txInput.build());
                }

                //Prepare outputs
                List<TrezorMessageBitcoin.TxOutput> outputs = new ArrayList<>();
                for(int outputIndex = 0; outputIndex < psbt.getPsbtOutputs().size(); outputIndex++) {
                    PSBTOutput psbtOutput = psbt.getPsbtOutputs().get(outputIndex);
                    TransactionOutput out = psbt.getTransaction().getOutputs().get(outputIndex);

                    TrezorMessageBitcoin.TxOutput.Builder txOutput = TrezorMessageBitcoin.TxOutput.newBuilder()
                            .setAmount(out.getValue())
                            .setScriptType(TrezorMessageBitcoin.OutputScriptType.PAYTOADDRESS);

                    Address address = out.getScript().getToAddress();
                    if(address != null) {
                        txOutput.setAddress(address.toString());
                    } else if(out.getScript().getChunks().size() >= 2 && out.getScript().getChunks().get(0).getOpcode() == ScriptOpCodes.OP_RETURN) {
                        txOutput.setScriptType(TrezorMessageBitcoin.OutputScriptType.PAYTOOPRETURN);
                        txOutput.setOpReturnData(ByteString.copyFrom(Arrays.copyOfRange(out.getScriptBytes(), 2, out.getScriptBytes().length)));
                    } else {
                        throw new IllegalArgumentException("Output " + outputIndex + " is not an address");
                    }

                    //Add the derivation path for change
                    Optional<ScriptType> optWitnessType = isWitness(out.getScript());
                    if(optWitnessType.isEmpty() || (optWitnessType.get().equals(ScriptType.P2WPKH) || optWitnessType.get().equals(ScriptType.P2WSH))) {
                        for(KeyDerivation keypath : psbtOutput.getDerivedPublicKeys().values()) {
                            if(!keypath.getMasterFingerprint().equals(masterFingerprint)) {
                                continue;
                            }

                            if(ScriptType.P2PKH.isScriptType(out.getScript())) {
                                txOutput.addAllAddressN(keypath.getDerivation().stream().map(ChildNumber::i).toList());
                                txOutput.clearAddress();
                            } else if(optWitnessType.isPresent()) {
                                txOutput.setScriptType(TrezorMessageBitcoin.OutputScriptType.PAYTOWITNESS);
                                txOutput.addAllAddressN(keypath.getDerivation().stream().map(ChildNumber::i).toList());
                                txOutput.clearAddress();
                            } else if(ScriptType.P2SH.isScriptType(out.getScript()) && psbtOutput.getRedeemScript() != null) {
                                optWitnessType = isWitness(psbtOutput.getRedeemScript());
                                if(optWitnessType.isPresent() && (optWitnessType.get() == ScriptType.P2WPKH || optWitnessType.get() == ScriptType.P2WSH)) {
                                    txOutput.setScriptType(TrezorMessageBitcoin.OutputScriptType.PAYTOP2SHWITNESS);
                                    txOutput.addAllAddressN(keypath.getDerivation().stream().map(ChildNumber::i).toList());
                                    txOutput.clearAddress();
                                }
                            }
                        }
                    } else if(optWitnessType.get().equals(ScriptType.P2TR)) {
                        for(ECKey key : psbtOutput.getTapDerivedPublicKeys().keySet()) {
                            Map<KeyDerivation, List<Sha256Hash>> keypath = psbtOutput.getTapDerivedPublicKeys().get(key);
                            for(KeyDerivation keypathKey : keypath.keySet()) {
                                //Script path change is not supported
                                if(key.equals(psbtOutput.getTapInternalKey()) && keypathKey.getMasterFingerprint().equals(masterFingerprint)) {
                                    txOutput.addAllAddressN(keypathKey.getDerivation().stream().map(ChildNumber::i).toList());
                                    txOutput.setScriptType(TrezorMessageBitcoin.OutputScriptType.PAYTOTAPROOT);
                                    txOutput.clearAddress();
                                }
                            }
                        }
                    }

                    //Add multisig info
                    if(psbtOutput.getWitnessScript() != null || psbtOutput.getRedeemScript() != null) {
                        Optional<TrezorMessageBitcoin.MultisigRedeemScriptType> optMultisigRedeemScriptType = getMultisig(
                                psbtOutput.getWitnessScript() != null ? psbtOutput.getWitnessScript() : psbtOutput.getRedeemScript(),
                                psbt.getExtendedPublicKeys(), psbtOutput.getDerivedPublicKeys());
                        if(optMultisigRedeemScriptType.isPresent()) {
                            txOutput.setMultisig(optMultisigRedeemScriptType.get());
                            if(optWitnessType.isEmpty()) {
                                txOutput.setScriptType(TrezorMessageBitcoin.OutputScriptType.PAYTOMULTISIG);
                            }
                        }
                    }

                    outputs.add(txOutput.build());
                }

                //Prepare prev txs
                Map<Sha256Hash, TrezorDevice.PrevTx> prevTxs = new LinkedHashMap<>();
                for(PSBTInput psbtInput : psbt.getPsbtInputs()) {
                    if(psbtInput.getNonWitnessUtxo() != null) {
                        Transaction prev = psbtInput.getNonWitnessUtxo();
                        TrezorMessageBitcoin.PrevTx prevTx = TrezorMessageBitcoin.PrevTx.newBuilder()
                                .setVersion((int)prev.getVersion())
                                .setLockTime((int)prev.getLocktime())
                                .setInputsCount(prev.getInputs().size())
                                .setOutputsCount(prev.getOutputs().size()).build();

                        List<TrezorMessageBitcoin.PrevInput> prevInputs = new ArrayList<>();
                        for(TransactionInput input : prev.getInputs()) {
                            TrezorMessageBitcoin.PrevInput prevInput = TrezorMessageBitcoin.PrevInput.newBuilder()
                                    .setPrevHash(ByteString.copyFrom(Utils.reverseBytes(serUInt256(input.getOutpoint().getHash().toBigInteger()))))
                                    .setPrevIndex((int)input.getOutpoint().getIndex())
                                    .setScriptSig(ByteString.copyFrom(input.getScriptBytes()))
                                    .setSequence((int)input.getSequenceNumber()).build();
                            prevInputs.add(prevInput);
                        }

                        List<TrezorMessageBitcoin.PrevOutput> prevOutputs = new ArrayList<>();
                        for(TransactionOutput output : prev.getOutputs()) {
                            TrezorMessageBitcoin.PrevOutput prevOutput = TrezorMessageBitcoin.PrevOutput.newBuilder()
                                    .setAmount(output.getValue())
                                    .setScriptPubkey(ByteString.copyFrom(output.getScriptBytes())).build();
                            prevOutputs.add(prevOutput);
                        }

                        prevTxs.put(Sha256Hash.wrap(Utils.reverseBytes(serUInt256(prev.getTxId().toBigInteger()))), new TrezorDevice.PrevTx(prevTx, prevInputs, prevOutputs));
                    }
                }

                //Sign the transaction
                List<TransactionSignature> signatures = trezorDevice.signTx(Network.get(), inputs, outputs, prevTxs,
                        psbt.getTransaction().getVersion(), psbt.getTransaction().getLocktime());

                for(int inputIndex = 0; inputIndex < psbt.getPsbtInputs().size(); inputIndex++) {
                    PSBTInput psbtInput = psbt.getPsbtInputs().get(inputIndex);
                    if(toIgnore.contains(inputIndex)) {
                        continue;
                    }
                    for(ECKey pubKey : psbtInput.getDerivedPublicKeys().keySet()) {
                        KeyDerivation keypath = psbtInput.getDerivedPublicKeys().get(pubKey);
                        if(keypath.getMasterFingerprint().equals(masterFingerprint) && !psbtInput.getPartialSignatures().containsKey(pubKey)) {
                            psbtInput.getPartialSignatures().put(pubKey, signatures.get(inputIndex));
                            break;
                        }
                    }
                    if(psbtInput.getTapInternalKey() != null && psbtInput.getTapKeyPathSignature() == null) {
                        psbtInput.setTapKeyPathSignature(signatures.get(inputIndex));
                    }
                }

                p++;
            }
        }

        return psbt;
    }

    private void ignoreInput(List<TrezorMessageBitcoin.TxInput> inputs, List<Integer> toIgnore, int inputIndex, TrezorMessageBitcoin.TxInput.Builder txInput) {
        txInput.addAllAddressN(KeyDerivation.parsePath(ScriptType.P2WPKH.getDefaultDerivationPath() + "/0/0").stream().map(ChildNumber::i).toList());
        txInput.setScriptType(TrezorMessageBitcoin.InputScriptType.SPENDWITNESS);
        inputs.add(txInput.build());
        toIgnore.add(inputIndex);
    }

    private Optional<TrezorMessageBitcoin.MultisigRedeemScriptType> getMultisig(Script script, Map<ExtendedKey, KeyDerivation> globalXpubs, Map<ECKey, KeyDerivation> derivedPublicKeys) {
        if(!ScriptType.MULTISIG.isScriptType(script)) {
            return Optional.empty();
        }

        List<TrezorMessageBitcoin.MultisigRedeemScriptType.HDNodePathType.Builder> pubkeys = new ArrayList<>();
        ECKey[] keys = ScriptType.MULTISIG.getPublicKeysFromScript(script);
        for(ECKey key : keys) {
            TrezorMessageCommon.HDNodeType hdNodeType = TrezorMessageCommon.HDNodeType.newBuilder()
                    .setDepth(0)
                    .setFingerprint(0)
                    .setChildNum(0)
                    .setChainCode(ByteString.copyFrom(Sha256Hash.ZERO_HASH.getBytes()))
                    .setPublicKey(ByteString.copyFrom(key.getPubKey())).build();
            pubkeys.add(TrezorMessageBitcoin.MultisigRedeemScriptType.HDNodePathType.newBuilder().setNode(hdNodeType).addAllAddressN(Collections.emptyList()));
        }

        for(TrezorMessageBitcoin.MultisigRedeemScriptType.HDNodePathType.Builder pubkey : pubkeys) {
            KeyDerivation derivation = derivedPublicKeys.get(ECKey.fromPublicOnly(pubkey.getNode().getPublicKey().toByteArray()));
            if(derivation != null) {
                for(ExtendedKey xpub : globalXpubs.keySet()) {
                    KeyDerivation globalDerivation = globalXpubs.get(xpub);
                    if(globalDerivation.getMasterFingerprint().equals(derivation.getMasterFingerprint()) &&
                            globalDerivation.getDerivation().equals(derivation.getDerivation().subList(0, globalDerivation.getDerivation().size()))) {
                        List<ChildNumber> childDerivation = derivation.getDerivation().subList(globalDerivation.getDerivation().size(), derivation.getDerivation().size());
                        pubkey.addAllAddressN(childDerivation.stream().map(ChildNumber::i).toList());
                        TrezorMessageCommon.HDNodeType hdNodeType = TrezorMessageCommon.HDNodeType.newBuilder()
                                .setDepth(xpub.getKey().getDepth())
                                .setFingerprint(new BigInteger(1, xpub.getKey().getParentFingerprint()).intValue())
                                .setChildNum(xpub.getKeyChildNumber().i())
                                .setChainCode(ByteString.copyFrom(xpub.getKey().getChainCode()))
                                .setPublicKey(ByteString.copyFrom(xpub.getKey().getPubKey())).build();
                        pubkey.setNode(hdNodeType);
                        break;
                    }
                }
            }
        }

        return Optional.of(TrezorMessageBitcoin.MultisigRedeemScriptType.newBuilder()
                .setM(ScriptType.MULTISIG.getThreshold(script))
                .addAllSignatures(IntStream.range(0, keys.length).mapToObj(i -> ByteString.empty()).toList())
                .addAllPubkeys(pubkeys.stream().map(TrezorMessageBitcoin.MultisigRedeemScriptType.HDNodePathType.Builder::build).toList()).build());
    }

    @Override
    String signMessage(String message, String path) throws DeviceException {
        try(TrezorDevice trezorDevice = new TrezorDevice(device, new PassphraseUI(passphrase), trezorModel)) {
            checkUnlocked(trezorDevice);

            TrezorMessageBitcoin.InputScriptType scriptType = TrezorMessageBitcoin.InputScriptType.SPENDADDRESS;
            List<ChildNumber> keypath = KeyDerivation.parsePath(path);
            keypath = keypath.subList(0, Math.min(3, keypath.size()));
            if(ScriptType.P2WPKH.getDefaultDerivation().equals(keypath)) {
                scriptType = TrezorMessageBitcoin.InputScriptType.SPENDWITNESS;
            } else if(ScriptType.P2SH_P2WPKH.getDefaultDerivation().equals(keypath)) {
                scriptType = TrezorMessageBitcoin.InputScriptType.SPENDP2SHWITNESS;
            }

            return trezorDevice.signMessage(Network.get(), path, message, scriptType);
        }
    }

    @Override
    String displaySinglesigAddress(String path, ScriptType scriptType) throws DeviceException {
        try(TrezorDevice trezorDevice = new TrezorDevice(device, new PassphraseUI(passphrase), trezorModel)) {
            checkUnlocked(trezorDevice);

            TrezorMessageBitcoin.InputScriptType inputScriptType = switch(scriptType) {
                case P2SH_P2WPKH -> TrezorMessageBitcoin.InputScriptType.SPENDP2SHWITNESS;
                case P2WPKH -> TrezorMessageBitcoin.InputScriptType.SPENDWITNESS;
                case P2PKH -> TrezorMessageBitcoin.InputScriptType.SPENDADDRESS;
                case P2TR -> {
                    if(!canSignTaproot(trezorDevice)) {
                        throw new DeviceException("This device does not support displaying Taproot addresses");
                    }
                    yield TrezorMessageBitcoin.InputScriptType.SPENDTAPROOT;
                }
                default -> throw new IllegalArgumentException("Unsupported script type " + scriptType);
            };

            return trezorDevice.getAddress(Network.get(), path, true, null, inputScriptType, false);
        }
    }

    @Override
    String displayMultisigAddress(OutputDescriptor outputDescriptor) throws DeviceException {
        try(TrezorDevice trezorDevice = new TrezorDevice(device, new PassphraseUI(passphrase), trezorModel)) {
            checkUnlocked(trezorDevice);

            List<TrezorMessageBitcoin.MultisigRedeemScriptType.HDNodePathType> pubkeys = new ArrayList<>();
            for(ExtendedKey xpub : outputDescriptor.sortExtendedPubKeys(outputDescriptor.getExtendedPublicKeys())) {
                List<ChildNumber> childDerivation = outputDescriptor.getChildDerivation(xpub);
                TrezorMessageCommon.HDNodeType hdNodeType = TrezorMessageCommon.HDNodeType.newBuilder()
                        .setDepth(xpub.getKey().getDepth())
                        .setFingerprint(new BigInteger(1, xpub.getKey().getParentFingerprint()).intValue())
                        .setChildNum(xpub.getKeyChildNumber().i())
                        .setChainCode(ByteString.copyFrom(xpub.getKey().getChainCode()))
                        .setPublicKey(ByteString.copyFrom(xpub.getKey().getPubKey())).build();

                pubkeys.add(TrezorMessageBitcoin.MultisigRedeemScriptType.HDNodePathType.newBuilder()
                        .setNode(hdNodeType)
                        .addAllAddressN(childDerivation.subList(1, childDerivation.size()).stream().map(ChildNumber::i).toList()).build());
            }

            TrezorMessageBitcoin.MultisigRedeemScriptType multisig = TrezorMessageBitcoin.MultisigRedeemScriptType.newBuilder()
                    .setM(outputDescriptor.getMultisigThreshold())
                    .addAllSignatures(IntStream.range(0, pubkeys.size()).mapToObj(i -> ByteString.empty()).toList())
                    .addAllPubkeys(pubkeys).build();

            TrezorMessageBitcoin.InputScriptType inputScriptType = switch(outputDescriptor.getScriptType()) {
                case P2SH_P2WSH -> TrezorMessageBitcoin.InputScriptType.SPENDP2SHWITNESS;
                case P2WSH -> TrezorMessageBitcoin.InputScriptType.SPENDWITNESS;
                case P2SH -> TrezorMessageBitcoin.InputScriptType.SPENDMULTISIG;
                default -> throw new IllegalArgumentException("Unsupported script type " + outputDescriptor.getScriptType());
            };

            for(ExtendedKey xpub : outputDescriptor.getExtendedPublicKeys()) {
                KeyDerivation keyDerivation = outputDescriptor.getKeyDerivation(xpub);
                String path = outputDescriptor.getKeyDerivation(xpub).extend(KeyDerivation.parsePath(outputDescriptor.getChildDerivationPath(xpub))).getDerivationPath();
                try {
                    return trezorDevice.getAddress(Network.get(), path, true, multisig, inputScriptType, false);
                } catch(DeviceException e) {
                    if(masterFingerprint != null && masterFingerprint.equals(keyDerivation.getMasterFingerprint())) {
                        throw e;
                    }
                }
            }

            throw new DeviceException("No path supplied matched device keys");
        }
    }

    @Override
    public boolean promptPin() throws DeviceException {
        try(TrezorDevice trezorDevice = new TrezorDevice(device, new PassphraseUI(passphrase), trezorModel)) {
            try {
                prepareDevice(trezorDevice);
            } catch(DeviceNotReadyException e) {
                //ignore, expected
            }

            if(!trezorDevice.getFeatures().getPinProtection()) {
                throw new DeviceException("This device does not need a PIN");
            }
            if(trezorDevice.getFeatures().getUnlocked()) {
                throw new DeviceException("The PIN has already been sent to this device");
            }
            if(Lark.isConsoleOutput()) {
                System.err.println("Use 'sendpin' to provide the number positions for the PIN as displayed on your device's screen");
                System.err.println(PIN_MATRIX_DESCRIPTION);
            }

            TrezorMessageBitcoin.GetPublicKey getPublicKey = TrezorMessageBitcoin.GetPublicKey.newBuilder()
                    .addAllAddressN(KeyDerivation.parsePath("m/44'/1'/0'").stream().map(ChildNumber::i).toList())
                    .setCoinName(trezorDevice.getCoinName(Network.TESTNET))
                    .setShowDisplay(false)
                    .setScriptType(TrezorMessageBitcoin.InputScriptType.SPENDADDRESS)
                    .build();
            trezorDevice.callRaw(getPublicKey);
            return true;
        }
    }

    @Override
    @SuppressWarnings("deprecation")
    public boolean sendPin(String pin) throws DeviceException {
        if(!pin.matches("\\d+")) {
            throw new IllegalArgumentException("Non-numeric PIN provided");
        }

        try(TrezorDevice trezorDevice = new TrezorDevice(device, new PassphraseUI(passphrase), trezorModel)) {
            Message message = trezorDevice.callRaw(TrezorMessageCommon.PinMatrixAck.newBuilder().setPin(pin).build());
            if(message instanceof TrezorMessageCommon.Failure) {
                TrezorMessageManagement.Features features = trezorDevice.refreshFeatures();
                if(!features.getPinProtection()) {
                    throw new DeviceException("This device does not need a PIN");
                }
                if(features.getUnlocked()) {
                    throw new DeviceException("The PIN has already been sent to this device");
                }
                return false;
            } else if(message instanceof TrezorMessageCommon.PassphraseRequest) {
                TrezorMessageCommon.PassphraseAck passphraseAck = TrezorMessageCommon.PassphraseAck.newBuilder()
                        .setPassphrase((String)trezorDevice.getUI().getPassphrase(false))
                        .setOnDevice(false).build();
                Message resp = trezorDevice.call(passphraseAck, Message.class);
                if(resp instanceof TrezorMessageCommon.Deprecated_PassphraseStateRequest) {
                    trezorDevice.callRaw(TrezorMessageCommon.Deprecated_PassphraseStateAck.newBuilder().build());
                }
            }

            return true;
        }
    }

    @Override
    public boolean togglePassphrase() throws DeviceException {
        if(passphrase == null) {
            passphrase = "";
        }

        try(TrezorDevice trezorDevice = new TrezorDevice(device, new PassphraseUI(passphrase), trezorModel)) {
            checkUnlocked(trezorDevice);

            try {
                trezorDevice.applySettings(null, !trezorDevice.getFeatures().getPassphraseProtection(),
                        null, null, null, null, null, null);
            } catch(DeviceException e) {
                if(Lark.isConsoleOutput() && trezorDevice.getModel() == TrezorModel.KEEPKEY) {
                    System.err.println("Confirm the action by entering your PIN");
                    System.err.println("Use 'sendpin' to provide the number positions for the PIN as displayed on your device's screen");
                    System.err.println(PIN_MATRIX_DESCRIPTION);
                }
            }

            return true;
        }
    }

    @Override
    public String getPath() {
        StringJoiner joiner = new StringJoiner(":");
        joiner.add(PATH_PREFIX);
        joiner.add(String.format("%03d", busNumber));
        for(int i = 0; i < portNumbers.capacity(); i++) {
            joiner.add(String.format("%01x", portNumbers.get(i)));
        }
        return joiner.toString();
    }

    @Override
    public HardwareType getHardwareType() {
        return HardwareType.TREZOR;
    }

    @Override
    public WalletModel getModel() {
        return model == null ? WalletModel.TREZOR_T : model;
    }

    @Override
    public Boolean needsPinSent() {
        return needsPinSent;
    }

    @Override
    public Boolean needsPassphraseSent() {
        return needsPassphraseSent;
    }

    @Override
    public String fingerprint() {
        return masterFingerprint;
    }

    @Override
    public boolean card() {
        return false;
    }

    @Override
    public String[][] warnings() {
        if(warnings.isEmpty()) {
            return new String[0][];
        } else {
            return new String[][] { warnings.toArray(new String[0]) };
        }
    }

    @Override
    public String getLabel() {
        return label;
    }

    @Override
    public String getProductModel() {
        return trezorModel == null ? WalletModel.TREZOR_T.toString().toLowerCase(Locale.ROOT) : trezorModel.getWalletModel().toString().toLowerCase(Locale.ROOT);
    }

    public void setPassphrase(String passphrase) {
        this.passphrase = passphrase;
    }

    public boolean canSignTaproot(TrezorDevice trezorDevice) {
        return trezorDevice.canSignTaproot();
    }
}
