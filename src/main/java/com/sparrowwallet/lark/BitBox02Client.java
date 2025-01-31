package com.sparrowwallet.lark;

import com.google.protobuf.ByteString;
import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTOutput;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.lark.bitbox02.*;
import com.sparrowwallet.lark.bitbox02.generated.Antiklepto;
import com.sparrowwallet.lark.bitbox02.generated.Btc;
import com.sparrowwallet.lark.bitbox02.generated.Common;
import com.sparrowwallet.lark.bitbox02.generated.Hww;
import org.hid4java.HidDevice;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

import static com.sparrowwallet.lark.bitbox02.BitBox02Device.*;

public class BitBox02Client extends HardwareClient {
    private static final Logger log = LoggerFactory.getLogger(BitBox02Client.class);

    private static final DeviceId BITBOX02_ID = new DeviceId(BITBOX02_VID, BITBOX02_PID);
    public static final int MAX_WALLET_NAME_LENGTH = 30;

    private final HidDevice hidDevice;
    private final BitBox02Edition edition;

    private BitBoxNoiseConfig noiseConfig = new BitBoxAppNoiseConfig();
    private String masterFingerprint;

    private static final SecureRandom secureRandom = new SecureRandom();

    private final ChildNumber PURPOSE_P2WPKH = ScriptType.P2WPKH.getDefaultDerivation().get(0);
    private final ChildNumber PURPOSE_P2WPKH_P2SH = ScriptType.P2SH_P2WPKH.getDefaultDerivation().get(0);

    private final List<ScriptType> SUPPORTED_PUB_KEY_PATHS = List.of(ScriptType.P2SH_P2WPKH, ScriptType.P2WPKH, ScriptType.P2TR, ScriptType.P2SH_P2WSH, ScriptType.P2WSH);

    public BitBox02Client(HidDevice hidDevice) throws DeviceException {
        if(BITBOX02_ID.matches(hidDevice) && (hidDevice.getUsagePage() == 0xFFFF || hidDevice.getInterfaceNumber() == 0) &&
                (BitBox02Edition.fromProductString(hidDevice.getProduct()) != null)) {
            this.hidDevice = hidDevice;
            this.edition = BitBox02Edition.fromProductString(hidDevice.getProduct());
        } else {
            throw new DeviceException("Not a BitBox02");
        }
    }

    @Override
    void initializeMasterFingerprint() throws DeviceException {
        try(BitBox02Device bitBox02Device = new BitBox02Device(hidDevice, new U2FHid(new HidPhysicalLayer(hidDevice)), noiseConfig)) {
            initializeMasterFingerprint(bitBox02Device);
        }
    }

    private void initializeMasterFingerprint(BitBox02Device bitBox02Device) throws DeviceException {
        if(masterFingerprint == null) {
            Hww.Request.Builder request = Hww.Request.newBuilder();
            request.setFingerprint(Common.RootFingerprintRequest.newBuilder().build());
            Hww.Response hwwResponse = bitBox02Device.msgQuery(request.build(), Hww.Response.ResponseCase.FINGERPRINT);
            this.masterFingerprint = Utils.bytesToHex(hwwResponse.getFingerprint().getFingerprint().toByteArray());
        }
    }

    /**
     * Fetch the public key at the derivation path.
     *
     * The BitBox02 has strict keypath validation.
     *
     * The only accepted keypaths for xpubs are (as of firmware v9.4.0):
     *
     * - `m/49'/0'/<account'>` for `p2wpkh-p2sh` (segwit wrapped in P2SH)
     * - `m/84'/0'/<account'>` for `p2wpkh` (native segwit v0)
     * - `m/86'/0'/<account'>` for `p2tr` (native segwit v1)
     * - `m/48'/0'/<account'>/2'` for p2wsh multisig (native segwit v0 multisig).
     * - `m/48'/0'/<account'>/1'` for p2wsh-p2sh multisig (p2sh-wrapped segwit v0 multisig).
     * - `m/48'/0'/<account'>` for p2wsh and p2wsh-p2sh multisig.
     *
     * `account'` can be between `0'` and `99'`.
     *
     * For address keypaths, append `/0/<address index>` for a receive and `/1/<change index>` for a change
     * address. Up to `10000` addresses are supported.
     *
     * In testnet mode, the second element must be `1'` (e.g. `m/49'/1'/...`).
     *
     * Public keys for the Legacy address type (i.e. P2PKH and P2SH multisig) derivation path are unsupported.
     *
     * @param path the derivation path
     * @return the xpub at the derivation path
     * @throws DeviceException if an error occurs
     */
    @Override
    ExtendedKey getPubKeyAtPath(String path) throws DeviceException {
        if(!isValidPath(path)) {
            throw new DeviceException("The BitBox02 does not support retrieving an xpub at " + path + ". Only standard segwit paths on the configured network are supported from account 0 to 99.");
        }

        try(BitBox02Device bitBox02Device = new BitBox02Device(hidDevice, new U2FHid(new HidPhysicalLayer(hidDevice)), noiseConfig)) {
            Hww.Request.Builder request = Hww.Request.newBuilder();
            request.setBtcPub(Btc.BTCPubRequest.newBuilder().setCoin(getCoin()).addAllKeypath(KeyDerivation.parsePath(path).stream().map(ChildNumber::i).toList())
                    .setXpubType(Network.get() == Network.MAINNET ? Btc.BTCPubRequest.XPubType.XPUB : Btc.BTCPubRequest.XPubType.TPUB).setDisplay(false));
            Hww.Response hwwResponse = bitBox02Device.msgQuery(request.build(), null);
            return ExtendedKey.fromDescriptor(hwwResponse.getPub().getPub());
        }
    }

    private boolean isValidPath(String path) {
        for(ScriptType scriptType : SUPPORTED_PUB_KEY_PATHS) {
            int account = scriptType.getAccount(path);
            if(account >= 0 && account < 100) {
                return true;
            }
        }

        if(path.matches("m/48'/[01]'/\\d{1,2}'")) {
            return true;
        }

        return false;
    }

    /**
     * Sign a transaction with the BitBox02.
     *
     * The BitBox02 allows mixing inputs of different script types (e.g. and `p2wpkh-p2sh` `p2wpkh`), as
     * long as the keypaths use the appropriate bip44 purpose field per input (e.g. `49'` and `84'`) and
     * all account indexes are the same.
     *
     * Transactions with legacy inputs are not supported.
     * @param psbt the PSBT to sign
     * @return the signed PSBT
     * @throws DeviceException if an error occurs
     */
    @Override
    PSBT signTransaction(PSBT psbt) throws DeviceException {
        try(BitBox02Device bitBox02Device = new BitBox02Device(hidDevice, new U2FHid(new HidPhysicalLayer(hidDevice)), noiseConfig)) {
            initializeMasterFingerprint(bitBox02Device);

            List<Btc.BTCScriptConfigWithKeypath> scriptConfigs = new ArrayList<>();
            List<TxInput> inputs = new ArrayList<>();
            Integer bip44Account = null;

            /* One pubkey per input. The pubkey identifies the key per input with which we sign. There
               must be exactly one pubkey per input that belongs to the BitBox02. */
            List<ECKey> foundPubKeys = new ArrayList<>();

            for(int i = 0; i < psbt.getPsbtInputs().size(); i++) {
                PSBTInput psbtInput = psbt.getPsbtInputs().get(i);

                if(psbtInput.getSigHash() != null && psbtInput.getSigHash() != SigHash.ALL && psbtInput.getSigHash() != SigHash.DEFAULT) {
                    throw new DeviceException("The BitBox02 only supports SIGHASH_ALL or SIGHASH_DEFAULT. Found sighash: " + psbtInput.getSigHash());
                }

                TransactionOutput utxo = null;
                Transaction prevTx = null;

                /* psbt_in.witness_utxo was originally used for segwit utxo's, but since it was
                   discovered that the amounts are not correctly committed to in the segwit sighash, the
                   full prevtx (non_witness_utxo) is supplied for both segwit and non-segwit inputs.
                   See
                   - https://medium.com/shiftcrypto/bitbox-app-firmware-update-6-2020-c70f733a5330
                   - https://blog.trezor.io/details-of-firmware-updates-for-trezor-one-version-1-9-1-and-trezor-model-t-version-2-3-1-1eba8f60f2dd.
                   - https://github.com/zkSNACKs/WalletWasabi/pull/3822
                   The BitBox02 requires all prevtxs if not all of the inputs are taproot. */

                if(psbtInput.getNonWitnessUtxo() != null) {
                    utxo = psbtInput.getNonWitnessUtxo().getOutputs().get((int)psbtInput.getInput().getOutpoint().getIndex());
                    prevTx = psbtInput.getNonWitnessUtxo();
                } else if(psbtInput.getWitnessUtxo() != null) {
                    utxo = psbtInput.getWitnessUtxo();
                }
                if(utxo == null) {
                    throw new DeviceException("No utxo found for input " + i);
                }

                Map<ECKey, KeyDerivation> derivedPubKeys = new HashMap<>(psbtInput.getDerivedPublicKeys());
                if(psbtInput.getTapInternalKey() != null) {
                    Map<ECKey, Map<KeyDerivation, List<Sha256Hash>>> tapDerivedPublicKeys = psbtInput.getTapDerivedPublicKeys();
                    if(tapDerivedPublicKeys != null) {
                        for(ECKey ecKey : tapDerivedPublicKeys.keySet()) {
                            Map<KeyDerivation, List<Sha256Hash>> tapKeyDerivationMap = tapDerivedPublicKeys.get(ecKey);
                            for(KeyDerivation keyDerivation : tapKeyDerivationMap.keySet()) {
                                if(!tapKeyDerivationMap.get(keyDerivation).isEmpty()) {
                                    throw new DeviceException("The BitBox02 does not support Taproot script path spending. Found " + tapKeyDerivationMap.size() + " leaf hashes");
                                }
                                derivedPubKeys.put(ecKey, keyDerivation);
                                break;
                            }
                        }
                    }
                }

                Optional<Map.Entry<ECKey, KeyDerivation>> optOurKey = findOurKey(bitBox02Device, derivedPubKeys);
                if(optOurKey.isEmpty()) {
                    throw new DeviceException("No key found for input " + i);
                }

                foundPubKeys.add(optOurKey.get().getKey());
                KeyDerivation keyDerivation = optOurKey.get().getValue();

                int inputAccount = psbtInput.getScriptType().getAccount(KeyDerivation.writePath(keyDerivation.getDerivation().subList(0, keyDerivation.getDerivation().size() - 2)));
                if(bip44Account == null) {
                    bip44Account = inputAccount;
                } else if(bip44Account != inputAccount) {
                    throw new DeviceException("The bip44 account index must be the same for all inputs and changes");
                }

                int scriptConfigIndex = addScriptConfig(scriptConfigs, getScriptConfigFromUtxo(psbt, utxo, keyDerivation.getDerivation().stream().map(ChildNumber::i).toList(),
                        psbtInput.getRedeemScript(), psbtInput.getWitnessScript()));

                inputs.add(new TxInput(psbtInput.getInput().getOutpoint().getHash(), (int)psbtInput.getInput().getOutpoint().getIndex(),
                        utxo.getValue(), psbtInput.getInput().getSequenceNumber(),
                        keyDerivation, scriptConfigIndex, prevTx));
            }

            List<Object> outputs = new ArrayList<>();

            for(int i = 0; i < psbt.getPsbtOutputs().size(); i++) {
                PSBTOutput psbtOutput = psbt.getPsbtOutputs().get(i);
                TransactionOutput txOutput = psbt.getTransaction().getOutputs().get(i);

                Map<ECKey, KeyDerivation> derivedPubKeys = new HashMap<>(psbtOutput.getDerivedPublicKeys());
                if(psbtOutput.getTapInternalKey() != null) {
                    Map<ECKey, Map<KeyDerivation, List<Sha256Hash>>> tapDerivedPublicKeys = psbtOutput.getTapDerivedPublicKeys();
                    if(tapDerivedPublicKeys != null) {
                        for(ECKey ecKey : tapDerivedPublicKeys.keySet()) {
                            Map<KeyDerivation, List<Sha256Hash>> tapKeyDerivationMap = tapDerivedPublicKeys.get(ecKey);
                            for(KeyDerivation keyDerivation : tapKeyDerivationMap.keySet()) {
                                if(!tapKeyDerivationMap.get(keyDerivation).isEmpty()) {
                                    throw new DeviceException("The BitBox02 does not support Taproot script path spending. Found " + tapKeyDerivationMap.size() + " leaf hashes");
                                }
                                derivedPubKeys.put(ecKey, keyDerivation);
                                break;
                            }
                        }
                    }
                }

                Optional<Map.Entry<ECKey, KeyDerivation>> optOurKey = findOurKey(bitBox02Device, derivedPubKeys);

                boolean isChange = optOurKey.isPresent() && optOurKey.get().getValue().getDerivation().get(optOurKey.get().getValue().getDerivation().size() - 2).equals(KeyPurpose.CHANGE.getPathIndex());
                if(isChange) {
                    KeyDerivation keyDerivation = optOurKey.get().getValue();
                    int scriptConfigIndex = addScriptConfig(scriptConfigs, getScriptConfigFromUtxo(psbt, txOutput, keyDerivation.getDerivation().stream().map(ChildNumber::i).toList(),
                            psbtOutput.getRedeemScript(), psbtOutput.getWitnessScript()));
                    outputs.add(new TxOutputInternal(keyDerivation, txOutput.getValue(), scriptConfigIndex));
                } else {
                    Btc.BTCOutputType type;
                    byte[] payload;
                    if(ScriptType.P2PKH.isScriptType(txOutput.getScript())) {
                        type = Btc.BTCOutputType.P2PKH;
                        payload = Arrays.copyOfRange(txOutput.getScript().getProgram(), 3,23);
                    } else if(ScriptType.P2WPKH.isScriptType(txOutput.getScript())) {
                        type = Btc.BTCOutputType.P2WPKH;
                        payload = Arrays.copyOfRange(txOutput.getScript().getProgram(), 2, txOutput.getScript().getProgram().length);
                    } else if(ScriptType.P2SH.isScriptType(txOutput.getScript())) {
                        type = Btc.BTCOutputType.P2SH;
                        payload = Arrays.copyOfRange(txOutput.getScript().getProgram(), 2, 22);
                    } else if(ScriptType.P2WSH.isScriptType(txOutput.getScript())) {
                        type = Btc.BTCOutputType.P2WSH;
                        payload = Arrays.copyOfRange(txOutput.getScript().getProgram(), 2, txOutput.getScript().getProgram().length);
                    } else if(ScriptType.P2TR.isScriptType(txOutput.getScript())) {
                        type = Btc.BTCOutputType.P2TR;
                        payload = Arrays.copyOfRange(txOutput.getScript().getProgram(), 2, txOutput.getScript().getProgram().length);
                    } else {
                        throw new DeviceException("Output type not recognized for output " + i);
                    }

                    outputs.add(new TxOutputExternal(type, payload, txOutput.getValue()));
                }
            }

            if(bip44Account == null) {
                throw new DeviceException("No account found");
            }

            Btc.BTCScriptConfig firstScriptConfig = scriptConfigs.getFirst().getScriptConfig();
            if(scriptConfigs.size() == 1 && firstScriptConfig.getConfigCase() == Btc.BTCScriptConfig.ConfigCase.MULTISIG) {
                String name = getWalletName(psbt, firstScriptConfig);
                registerScriptConfig(bitBox02Device, firstScriptConfig, scriptConfigs.getFirst().getKeypathList(), name == null ? "" : name);
            }

            List<Signature> sigs = btcSign(bitBox02Device, scriptConfigs, inputs, outputs, (int)psbt.getTransaction().getLocktime(), (int)psbt.getTransaction().getVersion());
            for(int i = 0; i < sigs.size(); i++) {
                Signature signature = sigs.get(i);
                PSBTInput psbtInput = psbt.getPsbtInputs().get(i);
                ECKey pubKey = foundPubKeys.get(i);

                BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature.signature, 0, 32));
                BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature.signature, 32, 64));

                if(psbtInput.getTapInternalKey() != null) {
                    psbtInput.setTapKeyPathSignature(new TransactionSignature(r, s, TransactionSignature.Type.SCHNORR));
                } else {
                    psbtInput.getPartialSignatures().put(pubKey, new TransactionSignature(r, s, TransactionSignature.Type.ECDSA));
                }
            }

            return psbt;
        }
    }

    private String getWalletName(PSBT psbt, Btc.BTCScriptConfig firstScriptConfig) {
        if(psbt.getExtendedPublicKeys().isEmpty()) {
            return null;
        }

        try {
            ScriptType scriptType = switch(firstScriptConfig.getMultisig().getScriptType()) {
                case P2WSH -> ScriptType.P2WSH;
                case P2WSH_P2SH -> ScriptType.P2SH_P2WSH;
                default -> throw new IllegalStateException("Unrecognised multisig script type: " + firstScriptConfig.getMultisig().getScriptType());
            };
            int m = firstScriptConfig.getMultisig().getThreshold();
            OutputDescriptor walletDescriptor = new OutputDescriptor(scriptType, m, psbt.getExtendedPublicKeys());
            return getWalletName(walletDescriptor);
        } catch(Exception e) {
            log.info("Unable to determine wallet name, will require BitBox02 to create one", e);
        }

        return null;
    }

    /**
     * coin: the first element of all provided keypaths must match the coin:
     * - BTC: 0 + HARDENED
     * - Testnets: 1 + HARDENED
     * - LTC: 2 + HARDENED
     * script_configs: types of all inputs and change outputs. The first element of all provided
     * keypaths must match this type:
     * - SCRIPT_P2PKH: 44 + HARDENED
     * - SCRIPT_P2WPKH_P2SH: 49 + HARDENED
     * - SCRIPT_P2WPKH: 84 + HARDENED
     * - SCRIPT_P2TR: 86 + HARDENED
     * inputs: transaction inputs. The previous transactions of the inputs need to be provided
     *   if `btc_sign_needs_prevtxs()` returns True.
     * outputs: transaction outputs. Can be an external output
     * (BTCOutputExternal) or an internal output for change (BTCOutputInternal).
     * version, locktime: reserved for future use.
     * Returns: list of (input index, signature) tuples.
     * Raises Bitbox02Exception with ERR_USER_ABORT on user abort.
     *
     * @param scriptConfigs script configurations
     * @param inputs inputs to sign
     * @param outputs outputs to sign
     * @param locktime transaction locktime
     * @param version transaction version
     *
     */
    private List<Signature> btcSign(BitBox02Device bitBox02Device, List<Btc.BTCScriptConfigWithKeypath> scriptConfigs, List<TxInput> inputs, List<Object> outputs, int locktime, int version) throws DeviceException {
        if(scriptConfigs.stream().anyMatch(this::isTaproot)) {
            bitBox02Device.requireAtLeastVersion(new Version("9.10.0"));
        }

        List<Signature> sigs = new ArrayList<>();
        boolean supportsAntiKlepto = (bitBox02Device.getVersion().compareTo(new Version("9.4.0")) >= 0);

        Hww.Request.Builder request = Hww.Request.newBuilder();
        request.setBtcSignInit(Btc.BTCSignInitRequest.newBuilder()
                .setCoin(getCoin())
                .addAllScriptConfigs(scriptConfigs)
                .setVersion(version)
                .setNumInputs(inputs.size())
                .setNumOutputs(outputs.size())
                .setLocktime(locktime)
                .setFormatUnit(Btc.BTCSignInitRequest.FormatUnit.DEFAULT).build());

        Btc.BTCSignNextResponse nextResponse = bitBox02Device.msgQuery(request.build(), Hww.Response.ResponseCase.BTC_SIGN_NEXT).getBtcSignNext();

        boolean isInputsPass2 = false;
        while(true) {
            if(nextResponse.getType() == Btc.BTCSignNextResponse.Type.INPUT) {
                int inputIndex = nextResponse.getIndex();
                TxInput input = inputs.get(inputIndex);

                Btc.BTCSignInputRequest.Builder btcSignInputRequest = Btc.BTCSignInputRequest.newBuilder()
                        .setPrevOutHash(ByteString.copyFrom(serUInt256(input.prevOutHash.toBigInteger())))
                        .setPrevOutIndex(input.prevOutIndex)
                        .setPrevOutValue(input.prevOutValue)
                        .setSequence((int)input.sequence)
                        .addAllKeypath(input.keyDerivation().getDerivation().stream().map(ChildNumber::i).toList())
                        .setScriptConfigIndex(input.scriptConfigIndex);

                boolean inputIsSchnorr = isTaproot(scriptConfigs.get(input.scriptConfigIndex));
                boolean performAntiKlepto = supportsAntiKlepto && isInputsPass2 && !inputIsSchnorr;

                ByteString hostNonce = null;
                if(performAntiKlepto) {
                    byte[] nonce = new byte[32];
                    secureRandom.nextBytes(nonce);
                    hostNonce = ByteString.copyFrom(nonce);
                    btcSignInputRequest.setHostNonceCommitment(Antiklepto.AntiKleptoHostNonceCommitment.newBuilder()
                            .setCommitment(ByteString.copyFrom(antiKleptoHostCommit(hostNonce.toByteArray()))).build());
                }

                request = Hww.Request.newBuilder();
                request.setBtcSignInput(btcSignInputRequest.build());

                nextResponse = bitBox02Device.msgQuery(request.build(), Hww.Response.ResponseCase.BTC_SIGN_NEXT).getBtcSignNext();

                if(performAntiKlepto) {
                    if(nextResponse.getType() != Btc.BTCSignNextResponse.Type.HOST_NONCE || !nextResponse.hasAntiKleptoSignerCommitment()) {
                        throw new DeviceException("Anti klepto response commitment not sent");
                    }

                    ByteString signerCommitment = nextResponse.getAntiKleptoSignerCommitment().getCommitment();
                    Btc.BTCRequest btcRequest = Btc.BTCRequest.newBuilder()
                            .setAntikleptoSignature(Antiklepto.AntiKleptoSignatureRequest.newBuilder().setHostNonce(hostNonce)).build();

                    nextResponse = bitBox02Device.btcMsgQuery(btcRequest, Btc.BTCResponse.ResponseCase.SIGN_NEXT).getSignNext();
                    if(log.isDebugEnabled()) {
                        log.debug("For input " + inputIndex + ", the host contributed the nonce " + Utils.bytesToHex(hostNonce.toByteArray()));
                    }

                    antiKleptoVerify(hostNonce.toByteArray(), signerCommitment.toByteArray(), nextResponse.getSignature().toByteArray());
                    if(log.isDebugEnabled()) {
                        log.debug("Antiklepto nonce verification PASSED for input " + inputIndex);
                    }
                }

                if(isInputsPass2) {
                    sigs.add(new Signature(inputIndex, nextResponse.getSignature().toByteArray()));
                }

                if(inputIndex == inputs.size() - 1) {
                    isInputsPass2 = true;
                }
            } else if(nextResponse.getType() == Btc.BTCSignNextResponse.Type.PREVTX_INIT) {
                Transaction prevTx = inputs.get(nextResponse.getIndex()).prevTx;
                if(prevTx == null) {
                    throw new DeviceException("Previous transaction missing");
                }

                Btc.BTCRequest.Builder btcRequest = Btc.BTCRequest.newBuilder()
                        .setPrevtxInit(Btc.BTCPrevTxInitRequest.newBuilder()
                                .setVersion((int)prevTx.getVersion())
                                .setNumInputs(prevTx.getInputs().size())
                                .setNumOutputs(prevTx.getOutputs().size())
                                .setLocktime((int)prevTx.getLocktime()).build());
                nextResponse = bitBox02Device.btcMsgQuery(btcRequest.build(), Btc.BTCResponse.ResponseCase.SIGN_NEXT).getSignNext();
            } else if(nextResponse.getType() == Btc.BTCSignNextResponse.Type.PREVTX_INPUT) {
                Transaction prevTx = inputs.get(nextResponse.getIndex()).prevTx;
                if(prevTx == null) {
                    throw new DeviceException("Previous transaction missing");
                }
                TransactionInput prevTxInput = prevTx.getInputs().get(nextResponse.getPrevIndex());
                Btc.BTCRequest.Builder btcRequest = Btc.BTCRequest.newBuilder()
                        .setPrevtxInput(Btc.BTCPrevTxInputRequest.newBuilder()
                                .setPrevOutHash(ByteString.copyFrom(serUInt256(prevTxInput.getOutpoint().getHash().toBigInteger())))
                                .setPrevOutIndex((int)prevTxInput.getOutpoint().getIndex())
                                .setSignatureScript(ByteString.copyFrom(prevTxInput.getScriptBytes()))
                                .setSequence((int)prevTxInput.getSequenceNumber()).build());
                nextResponse = bitBox02Device.btcMsgQuery(btcRequest.build(), Btc.BTCResponse.ResponseCase.SIGN_NEXT).getSignNext();
            } else if(nextResponse.getType() == Btc.BTCSignNextResponse.Type.PREVTX_OUTPUT) {
                Transaction prevTx = inputs.get(nextResponse.getIndex()).prevTx;
                if(prevTx == null) {
                    throw new DeviceException("Previous transaction missing");
                }
                TransactionOutput prevTxOutput = prevTx.getOutputs().get(nextResponse.getPrevIndex());
                Btc.BTCRequest.Builder btcRequest = Btc.BTCRequest.newBuilder()
                        .setPrevtxOutput(Btc.BTCPrevTxOutputRequest.newBuilder()
                                .setValue(prevTxOutput.getValue())
                                .setPubkeyScript(ByteString.copyFrom(prevTxOutput.getScriptBytes())).build());
                nextResponse = bitBox02Device.btcMsgQuery(btcRequest.build(), Btc.BTCResponse.ResponseCase.SIGN_NEXT).getSignNext();
            } else if(nextResponse.getType() == Btc.BTCSignNextResponse.Type.OUTPUT) {
                int outputIndex = nextResponse.getIndex();
                Object txOutput = outputs.get(outputIndex);

                request = Hww.Request.newBuilder();
                if(txOutput instanceof TxOutputInternal txOutputInternal) {
                    request.setBtcSignOutput(Btc.BTCSignOutputRequest.newBuilder()
                            .setOurs(true)
                            .setValue(txOutputInternal.value)
                            .addAllKeypath(txOutputInternal.keyDerivation.getDerivation().stream().map(ChildNumber::i).toList())
                            .setScriptConfigIndex(txOutputInternal.scriptConfigIndex).build());
                } else if(txOutput instanceof TxOutputExternal txOutputExternal) {
                    request.setBtcSignOutput(Btc.BTCSignOutputRequest.newBuilder()
                            .setOurs(false)
                            .setType(txOutputExternal.outputType)
                            .setPayload(ByteString.copyFrom(txOutputExternal.payload))
                            .setValue(txOutputExternal.value).build());
                }
                nextResponse = bitBox02Device.msgQuery(request.build(), Hww.Response.ResponseCase.BTC_SIGN_NEXT).getBtcSignNext();
            } else if(nextResponse.getType() == Btc.BTCSignNextResponse.Type.DONE) {
                break;
            } else {
                throw new DeviceException("Unexpected response");
            }
        }

        return sigs;
    }

    private boolean isTaproot(Btc.BTCScriptConfigWithKeypath scriptConfig) {
        return scriptConfig.getScriptConfig().getConfigCase() == Btc.BTCScriptConfig.ConfigCase.SIMPLE_TYPE &&
                scriptConfig.getScriptConfig().getSimpleType() == Btc.BTCScriptConfig.SimpleType.P2TR;
    }

    private byte[] antiKleptoHostCommit(byte[] hostNonce) {
        return Utils.taggedHash("s2c/ecdsa/data", hostNonce);
    }

    /**
     * Verifies that hostNonce was used to tweak the nonce during signature
     * generation according to k' = k + H(signerCommitment, hostNonce) by checking that
     * k'*G = signerCommitment + H(signerCommitment, hostNonce)*G.
     * Throws ECDSANonceException if the verification fails.
     *
     * @param hostNonce the host nonce
     * @param signerCommitment signed message
     * @param signature the signature
     */
    private void antiKleptoVerify(byte[] hostNonce, byte[] signerCommitment, byte[] signature) throws ECDSANonceException {
        ECKey signerCommitmentKey = ECKey.fromPublicOnly(signerCommitment);

        //Compute R = R1 + H(R1, host_nonce)*G. R1 is the client nonce commitment.
        byte[] tweak = Utils.taggedHash("s2c/ecdsa/point", Utils.concat(signerCommitment, hostNonce));
        ECKey tweakPubKey = ECKey.fromPrivate(tweak);
        ECKey tweakedNonce = tweakPubKey.add(signerCommitmentKey);
        BigInteger expectedSigR = tweakedNonce.moduloCurveOrder();
        BigInteger actualSigR = new BigInteger(1, Arrays.copyOfRange(signature, 0, 32));
        if(!actualSigR.equals(expectedSigR)) {
            throw new ECDSANonceException("Could not verify that the host nonce was contributed to the signature. If this happens repeatedly, the device might be attempting to leak the seed through the signature.");
        }
    }

    private Optional<Map.Entry<ECKey, KeyDerivation>> findOurKey(BitBox02Device bitBox02Device, Map<ECKey, KeyDerivation> keyDerivationMap) throws DeviceException {
        initializeMasterFingerprint(bitBox02Device);
        return keyDerivationMap.entrySet().stream().filter(entry -> entry.getValue().getMasterFingerprint().equals(masterFingerprint)).findFirst();
    }

    private int addScriptConfig(List<Btc.BTCScriptConfigWithKeypath> scriptConfigs, Btc.BTCScriptConfigWithKeypath scriptConfig) {
        for(int i = 0; i < scriptConfigs.size(); i++) {
            if(scriptConfigs.get(i).toString().equals(scriptConfig.toString())) {
                return i;
            }
        }

        scriptConfigs.add(scriptConfig);
        return scriptConfigs.size() - 1;
    }

    private Btc.BTCScriptConfigWithKeypath getScriptConfigFromUtxo(PSBT psbt, TransactionOutput output, List<Integer> keypath, Script redeemScript, Script witnessScript) throws DeviceException {
        if(ScriptType.P2PKH.isScriptType(output.getScript())) {
            throw new DeviceException("The BitBox02 does not support legacy p2pkh scripts");
        }
        if(ScriptType.P2WPKH.isScriptType(output.getScript())) {
            return Btc.BTCScriptConfigWithKeypath.newBuilder().setScriptConfig(Btc.BTCScriptConfig.newBuilder()
                    .setSimpleType(Btc.BTCScriptConfig.SimpleType.P2WPKH)).addAllKeypath(getHardenedPrefix(keypath)).build();
        }
        if(ScriptType.P2SH_P2WPKH.isScriptType(output.getScript()) && ScriptType.P2WPKH.isScriptType(redeemScript)) {
            return Btc.BTCScriptConfigWithKeypath.newBuilder().setScriptConfig(Btc.BTCScriptConfig.newBuilder()
                    .setSimpleType(Btc.BTCScriptConfig.SimpleType.P2WPKH_P2SH)).addAllKeypath(getHardenedPrefix(keypath)).build();
        }
        if(ScriptType.P2TR.isScriptType(output.getScript())) {
            return Btc.BTCScriptConfigWithKeypath.newBuilder().setScriptConfig(Btc.BTCScriptConfig.newBuilder()
                    .setSimpleType(Btc.BTCScriptConfig.SimpleType.P2TR)).addAllKeypath(getHardenedPrefix(keypath)).build();
        }

        if(ScriptType.P2WSH.isScriptType(output.getScript()) || (ScriptType.P2SH.isScriptType(output.getScript()) && ScriptType.P2WSH.isScriptType(redeemScript))) {
            if(ScriptType.MULTISIG.isScriptType(witnessScript)) {
                int threshold = ScriptType.MULTISIG.getThreshold(witnessScript);
                ECKey[] pubKeys = ScriptType.MULTISIG.getPublicKeysFromScript(witnessScript);
                /* We assume that all xpubs in the PSBT are part of the multisig. This is okay
                   since the BitBox02 enforces the same script type for all inputs and
                   changes. If that should change, we need to find and use the subset of xpubs
                   corresponding to the public keys in the current multisig script. */
                return buildMultisigScriptConfig(threshold, psbt.getExtendedPublicKeys(),
                        ScriptType.P2WSH.isScriptType(output.getScript()) ? Btc.BTCScriptConfig.Multisig.ScriptType.P2WSH : Btc.BTCScriptConfig.Multisig.ScriptType.P2WSH_P2SH);
            }
        }

        throw new DeviceException("Input or change script type not recognized");
    }

    private List<Integer> getHardenedPrefix(List<Integer> keypath) {
        return keypath.stream().takeWhile(ChildNumber::hasHardenedBit).toList();
    }

    @Override
    String signMessage(String message, String path) throws DeviceException {
        List<ChildNumber> fullPath = KeyDerivation.parsePath(path);

        Btc.BTCScriptConfig.SimpleType btcScriptConfigType;
        if(PURPOSE_P2WPKH.equals(fullPath.get(0))) {
            btcScriptConfigType = Btc.BTCScriptConfig.SimpleType.P2WPKH;
        } else if(PURPOSE_P2WPKH_P2SH.equals(fullPath.get(0))) {
            btcScriptConfigType = Btc.BTCScriptConfig.SimpleType.P2WPKH_P2SH;
        } else {
            throw new DeviceException("For message signing, the keypath bip44 purpose must be 84' or 49'");
        }

        if(Network.get() != Network.MAINNET) {
            throw new DeviceException("The BitBox02 only supports signing messages on mainnet");
        }

        Btc.BTCScriptConfigWithKeypath btcScriptConfigWithKeypath = Btc.BTCScriptConfigWithKeypath.newBuilder()
                .setScriptConfig(Btc.BTCScriptConfig.newBuilder().setSimpleType(btcScriptConfigType).build())
                .addAllKeypath(fullPath.stream().map(ChildNumber::i).toList()).build();

        try(BitBox02Device bitBox02Device = new BitBox02Device(hidDevice, new U2FHid(new HidPhysicalLayer(hidDevice)), noiseConfig)) {
            byte[] sigBytes = btcSignMsg(bitBox02Device, btcScriptConfigWithKeypath, message);
            return Base64.getEncoder().encodeToString(sigBytes);
        }
    }

    private byte[] btcSignMsg(BitBox02Device bitBox02Device, Btc.BTCScriptConfigWithKeypath btcScriptConfigWithKeypath, String message) throws DeviceException {
        bitBox02Device.requireAtLeastVersion(new Version("9.2.0"));

        Btc.BTCSignMessageRequest.Builder signMessage = Btc.BTCSignMessageRequest.newBuilder()
                .setCoin(getCoin())
                .setScriptConfig(btcScriptConfigWithKeypath)
                .setMsg(ByteString.copyFrom(message, StandardCharsets.UTF_8));

        Btc.BTCRequest.Builder btcRequest = Btc.BTCRequest.newBuilder();

        ByteString signature;

        boolean supportsAntiKlepto = (bitBox02Device.getVersion().compareTo(new Version("9.5.0")) >= 0);
        if(supportsAntiKlepto) {
            byte[] nonce = new byte[32];
            secureRandom.nextBytes(nonce);
            signMessage.setHostNonceCommitment(Antiklepto.AntiKleptoHostNonceCommitment.newBuilder()
                    .setCommitment(ByteString.copyFrom(antiKleptoHostCommit(nonce))).build());
            btcRequest.setSignMessage(signMessage.build());

            ByteString signerCommitment = bitBox02Device.btcMsgQuery(btcRequest.build(), Btc.BTCResponse.ResponseCase.ANTIKLEPTO_SIGNER_COMMITMENT)
                    .getAntikleptoSignerCommitment().getCommitment();

            btcRequest = Btc.BTCRequest.newBuilder().setAntikleptoSignature(Antiklepto.AntiKleptoSignatureRequest.newBuilder()
                    .setHostNonce(ByteString.copyFrom(nonce)));

            signature = bitBox02Device.btcMsgQuery(btcRequest.build(), Btc.BTCResponse.ResponseCase.SIGN_MESSAGE).getSignMessage().getSignature();
            antiKleptoVerify(nonce, signerCommitment.toByteArray(), signature.toByteArray());

            if(log.isDebugEnabled()) {
                log.debug("Antiklepto nonce verification PASSED");
            }
        } else {
            btcRequest.setSignMessage(signMessage.build());
            signature = bitBox02Device.btcMsgQuery(btcRequest.build(), Btc.BTCResponse.ResponseCase.SIGN_MESSAGE).getSignMessage().getSignature();
        }

        byte[] sigBytes = signature.toByteArray();

        ByteBuffer buf = ByteBuffer.allocate(65);
        buf.put((byte)(27 + 4 + sigBytes[64]));
        buf.put(Arrays.copyOfRange(sigBytes, 0, 64));

        return buf.array();
    }

    @Override
    String displaySinglesigAddress(String path, ScriptType scriptType) throws DeviceException {
        Btc.BTCScriptConfig scriptConfig = switch(scriptType) {
            case P2SH_P2WPKH -> Btc.BTCScriptConfig.newBuilder().setSimpleType(Btc.BTCScriptConfig.SimpleType.P2WPKH_P2SH).build();
            case P2WPKH -> Btc.BTCScriptConfig.newBuilder().setSimpleType(Btc.BTCScriptConfig.SimpleType.P2WPKH).build();
            case P2TR -> Btc.BTCScriptConfig.newBuilder().setSimpleType(Btc.BTCScriptConfig.SimpleType.P2TR).build();
            default -> throw new IllegalArgumentException("The BitBox02 does not support " + scriptType + " addresses");
        };

        try(BitBox02Device bitBox02Device = new BitBox02Device(hidDevice, new U2FHid(new HidPhysicalLayer(hidDevice)), noiseConfig)) {
            return displayAddress(bitBox02Device, scriptConfig, path);
        }
    }

    @Override
    String displayMultisigAddress(OutputDescriptor outputDescriptor) throws DeviceException {
        try(BitBox02Device bitBox02Device = new BitBox02Device(hidDevice, new U2FHid(new HidPhysicalLayer(hidDevice)), noiseConfig)) {
            initializeMasterFingerprint(bitBox02Device);

            Optional<ExtendedKey> optOurXpub = outputDescriptor.getExtendedPublicKeys().stream().filter(extKey -> outputDescriptor.getKeyDerivation(extKey).getMasterFingerprint().equals(masterFingerprint)).findFirst();
            if(optOurXpub.isEmpty()) {
                throw new DeviceException("This BitBox02 is not one of the cosigners");
            }
            ExtendedKey ourXpub = optOurXpub.get();

            Set<List<ChildNumber>> derivationPaths = new HashSet<>(outputDescriptor.getExtendedPublicKeys().stream().map(outputDescriptor::getChildDerivation).toList());
            if(derivationPaths.size() > 1) {
                throw new IllegalArgumentException("All multisig path suffixes must be the same for the BitBox02");
            }

            Map<ExtendedKey, KeyDerivation> keyOrigins = new LinkedHashMap<>();
            for(ExtendedKey extendedKey : outputDescriptor.sortExtendedPubKeys(outputDescriptor.getExtendedPublicKeys())) {
                keyOrigins.put(extendedKey, outputDescriptor.getKeyDerivation(extendedKey));
            }

            Btc.BTCScriptConfig.Multisig.ScriptType scriptType = switch(outputDescriptor.getScriptType()) {
                case P2SH_P2WSH -> Btc.BTCScriptConfig.Multisig.ScriptType.P2WSH_P2SH;
                case P2WSH -> Btc.BTCScriptConfig.Multisig.ScriptType.P2WSH;
                default -> throw new IllegalArgumentException("The BitBox02 does not support " + outputDescriptor.getScriptType() + " addresses");
            };

            Btc.BTCScriptConfigWithKeypath btcScriptConfigWithKeypath = buildMultisigScriptConfig(outputDescriptor.getMultisigThreshold(), keyOrigins, scriptType);
            String name = getWalletName(outputDescriptor);
            registerScriptConfig(bitBox02Device, btcScriptConfigWithKeypath.getScriptConfig(), btcScriptConfigWithKeypath.getKeypathList(), name == null ? "" : name);
            return displayAddress(bitBox02Device, btcScriptConfigWithKeypath.getScriptConfig(),
                    outputDescriptor.getKeyDerivation(ourXpub).extend(KeyDerivation.parsePath(outputDescriptor.getChildDerivationPath(ourXpub))).getDerivationPath());
        }
    }

    private String displayAddress(BitBox02Device bitBox02Device, Btc.BTCScriptConfig scriptConfig, String path) throws DeviceException {
        Hww.Request.Builder request = Hww.Request.newBuilder();
        request.setBtcPub(Btc.BTCPubRequest.newBuilder().setCoin(getCoin()).addAllKeypath(KeyDerivation.parsePath(path).stream().map(ChildNumber::i).toList())
                .setScriptConfig(scriptConfig).setDisplay(true));
        Hww.Response hwwResponse = bitBox02Device.msgQuery(request.build(), null);
        return hwwResponse.getPub().getPub();
    }

    private Btc.BTCScriptConfigWithKeypath buildMultisigScriptConfig(int threshold, Map<ExtendedKey, KeyDerivation> keyOrigins, Btc.BTCScriptConfig.Multisig.ScriptType scriptType) {
        List<ExtendedKey> keys = new ArrayList<>(keyOrigins.keySet());
        int ourXpubIndex = -1;
        List<Integer> ourKeyPath = Collections.emptyList();
        for(int i = 0; i < keyOrigins.size(); i++) {
            ExtendedKey key = keys.get(i);
            KeyDerivation keyDerivation = keyOrigins.get(key);
            if(keyDerivation.getMasterFingerprint().equals(masterFingerprint)) {
                ourXpubIndex = i;
                ourKeyPath = keyDerivation.getDerivation().stream().map(ChildNumber::i).toList();
                break;
            }
        }

        Btc.BTCScriptConfig.Multisig.Builder builder = Btc.BTCScriptConfig.Multisig.newBuilder()
                .setThreshold(threshold)
                .setScriptType(scriptType)
                .setOurXpubIndex(ourXpubIndex)
                .addAllXpubs(keys.stream().map(this::getXpub).toList());

        return Btc.BTCScriptConfigWithKeypath.newBuilder().setScriptConfig(Btc.BTCScriptConfig.newBuilder().setMultisig(builder.build())).addAllKeypath(ourKeyPath).build();
    }

    private void registerScriptConfig(BitBox02Device bitBox02Device, Btc.BTCScriptConfig btcScriptConfig, List<Integer> keypath, String name) throws DeviceException {
        boolean isRegistered = isScriptConfigRegistered(bitBox02Device, btcScriptConfig, keypath);
        if(!isRegistered) {
            if(name.isEmpty()) {
                bitBox02Device.requireAtLeastVersion(new Version("9.3.0"));
            }

            if(name.length() > MAX_WALLET_NAME_LENGTH) {
                throw new DeviceException("Multisig name is too long, must be 30 characters or less");
            }

            Btc.BTCScriptConfigRegistration scriptConfigRegistration = Btc.BTCScriptConfigRegistration.newBuilder()
                    .setCoin(getCoin())
                    .setScriptConfig(btcScriptConfig)
                    .addAllKeypath(keypath).build();

            Btc.BTCRegisterScriptConfigRequest registerScriptConfigRequest = Btc.BTCRegisterScriptConfigRequest.newBuilder()
                    .setRegistration(scriptConfigRegistration)
                    .setName(name)
                    .setXpubType(Btc.BTCRegisterScriptConfigRequest.XPubType.AUTO_XPUB_TPUB).build();

            Btc.BTCRequest request = Btc.BTCRequest.newBuilder().setRegisterScriptConfig(registerScriptConfigRequest).build();

            try {
                bitBox02Device.btcMsgQuery(request, Btc.BTCResponse.ResponseCase.SUCCESS);
            } catch(BitBox02Exception e) {
                if(e.getCode() == ERR_DUPLICATE_ENTRY) {
                    throw new DeviceException("A multisig account configuration with this name already exists. Choose another name.");
                }

                throw e;
            }
        }
    }

    private boolean isScriptConfigRegistered(BitBox02Device bitBox02Device, Btc.BTCScriptConfig btcScriptConfig, List<Integer> keypath) throws DeviceException {
        Btc.BTCRequest.Builder request = Btc.BTCRequest.newBuilder();
        request.setIsScriptConfigRegistered(Btc.BTCIsScriptConfigRegisteredRequest.newBuilder()
                .setRegistration(Btc.BTCScriptConfigRegistration.newBuilder()
                        .setCoin(getCoin())
                        .setScriptConfig(btcScriptConfig)
                        .addAllKeypath(keypath)).build());
        Btc.BTCResponse response = bitBox02Device.btcMsgQuery(request.build(), Btc.BTCResponse.ResponseCase.IS_SCRIPT_CONFIG_REGISTERED);
        return response.getIsScriptConfigRegistered().getIsRegistered();
    }

    private Common.XPub getXpub(ExtendedKey xpub) {
        return Common.XPub.newBuilder()
                .setChainCode(ByteString.copyFrom(xpub.getKey().getChainCode()))
                .setPublicKey(ByteString.copyFrom(xpub.getKey().getPubKey()))
                .setParentFingerprint(ByteString.copyFrom(xpub.getParentFingerprint()))
                .setChildNum(xpub.getKey().getChildNumber().i())
                .setDepth(ByteString.copyFrom(ByteBuffer.allocate(1).put((byte)xpub.getKey().getDepth()).array())).build();
    }

    private Btc.BTCCoin getCoin() {
        return Network.get() == Network.MAINNET ? Btc.BTCCoin.BTC : Btc.BTCCoin.TBTC;
    }

    @Override
    protected String getWalletName(OutputDescriptor walletDescriptor) {
        String name = super.getWalletName(walletDescriptor);
        if(name == null || name.trim().isEmpty()) {
            return null;
        }

        name = name.trim().replaceAll("[^\\x20-\\x7E]", "_");
        if(name.length() > MAX_WALLET_NAME_LENGTH) {
            name = name.substring(0, MAX_WALLET_NAME_LENGTH);
        }

        return name;
    }

    @Override
    public boolean togglePassphrase() throws DeviceException {
        try(BitBox02Device bitBox02Device = new BitBox02Device(hidDevice, new U2FHid(new HidPhysicalLayer(hidDevice)), noiseConfig)) {
            bitBox02Device.togglePassphrase();
            return true;
        }
    }

    @Override
    public String getPath() {
        return hidDevice.getPath();
    }

    @Override
    public HardwareType getHardwareType() {
        return HardwareType.BITBOX_02;
    }

    @Override
    public WalletModel getModel() {
        return WalletModel.BITBOX_02;
    }

    @Override
    public String getProductModel() {
        return getType() + "_" + edition.getName();
    }

    @Override
    public Boolean needsPinSent() {
        return false;
    }

    @Override
    public Boolean needsPassphraseSent() {
        return false;
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
        return new String[0][];
    }

    public void setNoiseConfig(BitBoxNoiseConfig noiseConfig) {
        this.noiseConfig = noiseConfig;
    }

    private record TxInput(Sha256Hash prevOutHash, int prevOutIndex, long prevOutValue, long sequence, KeyDerivation keyDerivation, int scriptConfigIndex, Transaction prevTx) {}
    private record TxOutputExternal(Btc.BTCOutputType outputType, byte[] payload, long value) {}
    private record TxOutputInternal(KeyDerivation keyDerivation, long value, int scriptConfigIndex) {}
    private record Signature(int index, byte[] signature) {}
}
