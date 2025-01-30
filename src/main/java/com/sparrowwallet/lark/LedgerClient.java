package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTParseException;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.lark.ledger.*;
import com.sparrowwallet.lark.ledger.wallet.MultisigWalletPolicy;
import com.sparrowwallet.lark.ledger.wallet.WalletPolicy;
import com.sparrowwallet.lark.ledger.wallet.WalletType;
import org.hid4java.HidDevice;

import java.util.*;

public class LedgerClient extends HardwareClient {

    private final HidDevice hidDevice;
    private final LedgerModel ledgerModel;

    private String masterFingerprint;
    private Map<OutputDescriptor, byte[]> walletRegistrations = new HashMap<>();

    public LedgerClient(HidDevice hidDevice) throws DeviceException {
        if(LedgerModel.getDeviceIds().stream().anyMatch(deviceId -> deviceId.getVendorId() == hidDevice.getVendorId() && deviceId.getProductId() == hidDevice.getProductId() >> 8) &&
                (hidDevice.getUsagePage() == 0xFFA0 || hidDevice.getInterfaceNumber() == 0)) {
            this.hidDevice = hidDevice;
            this.ledgerModel = LedgerModel.getLedgerModel(hidDevice.getProductId() >> 8);
        } else {
            throw new DeviceException("Not a Ledger");
        }
    }

    private LedgerDevice getLedgerDevice(HidDevice hidDevice) throws DeviceException {
        try {
            NewLedgerDevice newLedgerDevice = new NewLedgerDevice(new HIDTransport(hidDevice));
            LedgerDevice.LedgerVersion ledgerVersion = newLedgerDevice.getVersion();
            return ledgerVersion.isLegacy() ? new LegacyLedgerDevice(new HIDTransport(hidDevice), ledgerVersion) : newLedgerDevice;
        } catch(Exception e) {
            throw new DeviceException(e.getMessage(), e);
        }
    }

    @Override
    void initializeMasterFingerprint() throws DeviceException {
        try(LedgerDevice ledgerDevice = getLedgerDevice(hidDevice)) {
            getMasterFingerprint(ledgerDevice);
        }
    }

    private void getMasterFingerprint(LedgerDevice ledgerDevice) throws DeviceException {
        this.masterFingerprint = ledgerDevice.getMasterFingerprint();
    }

    @Override
    ExtendedKey getPubKeyAtPath(String path) throws DeviceException {
        try(LedgerDevice ledgerDevice = getLedgerDevice(hidDevice)) {
            return ledgerDevice.getExtendedPubkey(path, false);
        }
    }

    @Override
    PSBT signTransaction(PSBT psbt) throws DeviceException {
        try(LedgerDevice ledgerDevice = getLedgerDevice(hidDevice)) {
            getMasterFingerprint(ledgerDevice);

            if(ledgerDevice instanceof LegacyLedgerDevice) {
                WalletPolicy walletPolicy = new WalletPolicy("", "wpkh(@0/**)", List.of(""));
                List<LedgerDevice.Signature> signatures = ledgerDevice.signPsbt(psbt, walletPolicy, null);

                for(LedgerDevice.Signature signature : signatures) {
                    PSBTInput psbtInput = psbt.getPsbtInputs().get(signature.inputIndex());
                    psbtInput.getPartialSignatures().put(signature.ecKey(), signature.transactionSignature());
                }

                return psbt;
            } else {
                PSBT psbt2 = new PSBT(psbt.serialize());
                if(psbt2.getVersion() == null || psbt2.getVersion() == 0) {
                    psbt2.convertVersion(2);
                }

                Map<Sha256Hash, Wallet> wallets = new HashMap<>();
                Map<Integer, ECKey> pubkeys = new HashMap<>();

                for(int inputIndex = 0; inputIndex < psbt2.getPsbtInputs().size(); inputIndex++) {
                    PSBTInput psbtInput = psbt2.getPsbtInputs().get(inputIndex);
                    TransactionOutput utxo = null;
                    Script script;
                    if(psbtInput.getWitnessUtxo() != null) {
                        utxo = psbtInput.getWitnessUtxo();
                    }
                    if(psbtInput.getNonWitnessUtxo() != null) {
                        utxo = psbtInput.getNonWitnessUtxo().getOutputs().get(psbtInput.getPrevIndex().intValue());
                        psbtInput.setWitnessUtxo(utxo);
                    }
                    if(utxo == null) {
                        continue;
                    }
                    script = utxo.getScript();

                    boolean p2sh = false;
                    if(ScriptType.P2SH.isScriptType(script)) {
                        if(psbtInput.getRedeemScript() == null) {
                            continue;
                        }
                        script = psbtInput.getRedeemScript();
                        p2sh = true;
                    }

                    ScriptType scriptType = ScriptType.P2PKH;
                    Optional<ScriptType> optWitnessType = isWitness(script);
                    if(optWitnessType.isPresent()) {
                        ScriptType witnessType = optWitnessType.get();
                        if(p2sh) {
                            if(witnessType.equals(ScriptType.P2WPKH)) {
                                scriptType = ScriptType.P2SH_P2WPKH;
                            } else if(witnessType.equals(ScriptType.P2WSH)) {
                                scriptType = ScriptType.P2SH_P2WSH;
                            } else {
                                throw new IllegalArgumentException("Cannot have witness v1+ in " + ScriptType.P2SH);
                            }
                        } else {
                            if(witnessType.equals(ScriptType.P2WPKH)) {
                                scriptType = ScriptType.P2WPKH;
                            } else if(witnessType.equals(ScriptType.P2WSH)) {
                                scriptType = ScriptType.P2WSH;
                            } else if(witnessType.equals(ScriptType.P2TR)) {
                                scriptType = ScriptType.P2TR;
                            } else {
                                continue;
                            }
                        }
                    }

                    if(ScriptType.P2WSH.isScriptType(script)) {
                        if(psbtInput.getWitnessScript() == null) {
                            continue;
                        }
                        script = psbtInput.getWitnessScript();
                    }

                    if(ScriptType.MULTISIG.isScriptType(script)) {
                        int m = ScriptType.MULTISIG.getThreshold(script);
                        ECKey[] keys = ScriptType.MULTISIG.getPublicKeysFromScript(script);

                        Map<ExtendedKey, KeyDerivation> extendedPublicKeys = new LinkedHashMap<>();
                        boolean ok = true;
                        for(ECKey key : keys) {
                            if(psbtInput.getDerivedPublicKeys().containsKey(key)) {
                                KeyDerivation origin = psbtInput.getDerivedPublicKeys().get(key);
                                if(masterFingerprint.equals(origin.getMasterFingerprint())) {
                                    pubkeys.put(inputIndex, key);
                                }
                                for(ExtendedKey xpub : psbt2.getExtendedPublicKeys().keySet()) {
                                    KeyDerivation xpubOrigin = psbt2.getExtendedPublicKeys().get(xpub);
                                    if(xpubOrigin.getMasterFingerprint().equals(origin.getMasterFingerprint()) &&
                                            xpubOrigin.getDerivation().equals(origin.getDerivation().subList(0, xpubOrigin.getDerivation().size()))) {
                                        extendedPublicKeys.put(xpub, xpubOrigin);
                                        break;
                                    }
                                }
                            } else {
                                ok = false;
                            }
                        }

                        if(!ok) {
                            continue;
                        }

                        if(scriptType == ScriptType.P2PKH) {
                            scriptType = ScriptType.P2SH;
                        }

                        OutputDescriptor walletDescriptor = new OutputDescriptor(scriptType, m, extendedPublicKeys);
                        List<String> keyExprs = walletDescriptor.copy(false).getExtendedPublicKeys().stream()
                                .map(xpub -> OutputDescriptor.writeKey(xpub, walletDescriptor.getKeyDerivation(xpub), null, true, true, true)).toList();
                        MultisigWalletPolicy mswp = new MultisigWalletPolicy(getWalletNameOrDefault(walletDescriptor, psbt), scriptType, m, keyExprs);
                        Sha256Hash mswpId = mswp.id();
                        if(!wallets.containsKey(mswpId)) {
                            Sha256Hash registeredWalletId = getWalletRegistration(ledgerDevice, walletDescriptor, mswp);
                            wallets.put(mswpId, new Wallet(SigningPriority.fromScriptType(scriptType), scriptType, mswp, registeredWalletId));
                        }
                    } else {
                        for(ECKey key : psbtInput.getDerivedPublicKeys().keySet()) {
                            KeyDerivation origin = psbtInput.getDerivedPublicKeys().get(key);
                            if(masterFingerprint.equals(origin.getMasterFingerprint())) {
                                if(!ScriptType.MULTISIG.isScriptType(script)) {
                                    processOrigin(ledgerDevice, wallets, scriptType, origin);
                                }
                                pubkeys.put(inputIndex, key);
                            }
                        }

                        for(ECKey key : psbtInput.getTapDerivedPublicKeys().keySet()) {
                            Map<KeyDerivation, List<Sha256Hash>> keypath = psbtInput.getTapDerivedPublicKeys().get(key);
                            for(KeyDerivation origin : keypath.keySet()) {
                                //Note script path signing is not currently supported
                                if(key.equals(psbtInput.getTapInternalKey()) && origin.getMasterFingerprint().equals(masterFingerprint)) {
                                    processOrigin(ledgerDevice, wallets, scriptType, origin);
                                    pubkeys.put(inputIndex, key);
                                }
                            }
                        }
                    }
                }

                // For each wallet, sign
                List<Wallet> sortedWallets = new ArrayList<>(wallets.values());
                sortedWallets.sort(Comparator.comparing(o -> o.signingPriority));
                for(Wallet wallet : sortedWallets) {
                    if(wallet.scriptType() == ScriptType.P2PKH || wallet.scriptType() == ScriptType.P2SH) {
                        for(PSBTInput psbtInput : psbt2.getPsbtInputs()) {
                            TransactionOutput utxo = null;
                            if(psbtInput.getWitnessUtxo() != null) {
                                utxo = psbtInput.getWitnessUtxo();
                            }
                            if(utxo == null) {
                                continue;
                            }
                            Optional<ScriptType> optWitness = isWitness(utxo.getScript());
                            if(optWitness.isEmpty()) {
                                psbtInput.setWitnessUtxo(null);
                            }
                        }
                    }

                    List<LedgerDevice.Signature> signatures = ledgerDevice.signPsbt(psbt2, wallet.walletPolicy(), wallet.registeredHmac());

                    for(LedgerDevice.Signature signature : signatures) {
                        PSBTInput psbtInput = psbt2.getPsbtInputs().get(signature.inputIndex());

                        TransactionOutput utxo = null;
                        if(psbtInput.getWitnessUtxo() != null) {
                            utxo = psbtInput.getWitnessUtxo();
                        }
                        if(psbtInput.getNonWitnessUtxo() != null) {
                            utxo = psbtInput.getNonWitnessUtxo().getOutputs().get(psbtInput.getPrevIndex().intValue());
                        }
                        if(utxo == null) {
                            throw new IllegalArgumentException("The previous transaction output must be provided");
                        }

                        Optional<ScriptType> optWitness = isWitness(utxo.getScript());
                        if(optWitness.isPresent() && optWitness.get() == ScriptType.P2TR) {
                            //Keypath signature is assumed
                            psbtInput.setTapKeyPathSignature(signature.transactionSignature());
                        } else {
                            psbtInput.getPartialSignatures().put(signature.ecKey(), signature.transactionSignature());
                        }
                    }
                }

                for(int inputIndex = 0; inputIndex < psbt2.getPsbtInputs().size(); inputIndex++) {
                    PSBTInput psbtInput = psbt2.getPsbtInputs().get(inputIndex);
                    PSBTInput origInput = psbt.getPsbtInputs().get(inputIndex);
                    origInput.getPartialSignatures().putAll(psbtInput.getPartialSignatures());
                    if(psbtInput.getTapKeyPathSignature() != null && origInput.getTapKeyPathSignature() == null) {
                        origInput.setTapKeyPathSignature(psbtInput.getTapKeyPathSignature());
                    }
                }

                return psbt;
            }
        } catch(PSBTParseException e) {
            throw new IllegalArgumentException("Could not reparse PSBT", e);
        }
    }

    private Sha256Hash getWalletRegistration(LedgerDevice ledgerDevice, OutputDescriptor outputDescriptor, MultisigWalletPolicy mswp) throws DeviceException {
        OutputDescriptor walletDescriptor = outputDescriptor.copy(false);
        if(walletRegistrations.containsKey(walletDescriptor)) {
            if(walletRegistrations.get(walletDescriptor).length != 32) {
                throw new IllegalStateException("Wallet registration was not 32 bytes");
            }
            return Sha256Hash.wrap(walletRegistrations.get(walletDescriptor));
        }

        LedgerDevice.WalletRegistration registration = ledgerDevice.registerWallet(mswp);
        Sha256Hash registeredWalletId = registration.hmac();
        walletNames.put(walletDescriptor, mswp.getName());
        walletRegistrations.put(walletDescriptor, registeredWalletId.getBytes());
        return registeredWalletId;
    }

    private void processOrigin(LedgerDevice ledgerDevice, Map<Sha256Hash, Wallet> wallets, ScriptType scriptType, KeyDerivation origin) throws DeviceException {
        if(!isStandardPath(origin.getDerivation(), scriptType)) {
            //Non default wallets are not currently supported
            return;
        }

        WalletPolicy walletPolicy = getSingleSigWalletPolicy(ledgerDevice, scriptType, origin.getDerivation().get(2).num());
        wallets.put(walletPolicy.id(), new Wallet(SigningPriority.fromScriptType(scriptType), scriptType, walletPolicy, null));
    }

    private boolean isStandardPath(List<ChildNumber> path, ScriptType scriptType) {
        List<ChildNumber> standard = scriptType.getDefaultDerivation();

        if(path.size() != 5) {
            return false;
        }
        if(!path.stream().limit(3).allMatch(ChildNumber::isHardened)) {
            return false;
        }
        if(path.get(3).isHardened() || path.get(4).isHardened()) {
            return false;
        }
        if(!path.get(0).equals(standard.get(0))) {
            return false;
        }
        if(Network.get() == Network.MAINNET && !path.get(1).equals(ChildNumber.ZERO_HARDENED)) {
            return false;
        }
        if(Network.get() != Network.MAINNET && !path.get(1).equals(ChildNumber.ONE_HARDENED)) {
            return false;
        }
        if(!path.get(3).equals(ChildNumber.ZERO) && !path.get(3).equals(ChildNumber.ONE)) {
            return false;
        }
        return true;
    }

    private WalletPolicy getSingleSigWalletPolicy(LedgerDevice ledgerDevice, ScriptType scriptType, int account) throws DeviceException {
        String template = switch(scriptType) {
            case P2PKH -> "pkh(@0/**)";
            case P2WPKH -> "wpkh(@0/**)";
            case P2SH_P2WPKH -> "sh(wpkh(@0/**))";
            case P2TR -> "tr(@0/**)";
            default -> throw new IllegalStateException("Unexpected script type: " + scriptType);
        };

        List<ChildNumber> path = scriptType.getDefaultDerivation(account);
        KeyDerivation origin = new KeyDerivation(this.masterFingerprint, path);
        ExtendedKey xpub = ledgerDevice.getExtendedPubkey(origin.getDerivationPath(), false);
        String keyExpr = OutputDescriptor.writeKey(xpub, origin, null, true, true, true);
        return new WalletPolicy("", template, List.of(keyExpr));
    }

    @Override
    String signMessage(String message, String path) throws DeviceException {
        List<ChildNumber> keyPath = KeyDerivation.parsePath(path);
        String rewrittenPath = KeyDerivation.writePath(keyPath, true);

        try(LedgerDevice ledgerDevice = getLedgerDevice(hidDevice)) {
            return ledgerDevice.signMessage(message, rewrittenPath);
        }
    }

    @Override
    String displaySinglesigAddress(String path, ScriptType scriptType) throws DeviceException {
        try(LedgerDevice ledgerDevice = getLedgerDevice(hidDevice)) {
            List<ChildNumber> keyPath = KeyDerivation.parsePath(path);
            getMasterFingerprint(ledgerDevice);
            WalletPolicy walletPolicy;
            if(ledgerDevice instanceof LegacyLedgerDevice) {
                String template = switch(scriptType) {
                    case P2PKH -> "pkh(@0/**)";
                    case P2WPKH -> "wpkh(@0/**)";
                    case P2SH_P2WPKH -> "sh(wpkh(@0/**))";
                    case P2TR -> throw new DeviceException("Taproot is not supported by this version of the Bitcoin App");
                    default -> throw new IllegalArgumentException("Unexpected script type: " + scriptType);
                };

                String keysInfo = OutputDescriptor.writeKey(null, new KeyDerivation(masterFingerprint, path), null, true, false, true);
                walletPolicy = new WalletPolicy("", template, List.of(keysInfo));
            } else {
                if(!isStandardPath(keyPath, scriptType)) {
                    throw new DeviceException("Ledger requires BIP 44 standard paths");
                }
                walletPolicy = getSingleSigWalletPolicy(ledgerDevice, scriptType, keyPath.get(2).num());
            }

            return ledgerDevice.getWalletAddress(walletPolicy, null, keyPath.get(keyPath.size() - 2).num(), keyPath.get(keyPath.size() - 1).num(), true);
        }
    }

    @Override
    String displayMultisigAddress(OutputDescriptor outputDescriptor) throws DeviceException {
        try(LedgerDevice ledgerDevice = getLedgerDevice(hidDevice)) {
            if(ledgerDevice instanceof LegacyLedgerDevice) {
                throw new DeviceException("Displaying multisignature addresses is not supported by this version of the Bitcoin App");
            }

            if(!outputDescriptor.getExtendedPublicKeys().stream().map(outputDescriptor::getChildDerivation).allMatch(this::isValidDerivationPath)) {
                throw new DeviceException("Ledger Bitcoin app requires all derivation paths to end with /0/*, or all with /1/* for multisig");
            }

            if(outputDescriptor.getExtendedPublicKeys().stream().map(outputDescriptor::getKeyDerivation).anyMatch(kd -> kd.getDerivation().size() > 4)) {
                throw new DeviceException("Ledger Bitcoin app requires extended keys with derivation length at most 4");
            }

            List<String> keyExprs = outputDescriptor.copy(false).getExtendedPublicKeys().stream()
                    .map(xpub -> OutputDescriptor.writeKey(xpub, outputDescriptor.getKeyDerivation(xpub), null, true, true, true)).toList();

            MultisigWalletPolicy mswp = new MultisigWalletPolicy(getWalletNameOrDefault(outputDescriptor), outputDescriptor.getScriptType(), outputDescriptor.getMultisigThreshold(), keyExprs);
            Sha256Hash registeredWalletId = getWalletRegistration(ledgerDevice, outputDescriptor, mswp);

            List<ChildNumber> childPath = outputDescriptor.getChildDerivation(outputDescriptor.getExtendedPublicKeys().iterator().next());
            return ledgerDevice.getWalletAddress(mswp, registeredWalletId, childPath.get(1).num(), childPath.get(2).num(), true);
        }
    }

    private boolean isValidDerivationPath(List<ChildNumber> derivationPath) {
        return derivationPath.size() == 3 && (derivationPath.get(1).equals(ChildNumber.ZERO) || derivationPath.get(1).equals(ChildNumber.ONE)) && !derivationPath.get(2).isHardened();
    }

    @Override
    public String getPath() {
        return hidDevice.getPath();
    }

    @Override
    public HardwareType getHardwareType() {
        return HardwareType.LEDGER;
    }

    @Override
    public String getProductModel() {
        return ledgerModel.getName();
    }

    @Override
    public WalletModel getModel() {
        return ledgerModel.getWalletModel();
    }

    @Override
    public Boolean needsPinSent() {
        return masterFingerprint == null ? null : false;
    }

    @Override
    public Boolean needsPassphraseSent() {
        return masterFingerprint == null ? null : false;
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

    public void setWalletRegistrations(Map<OutputDescriptor, byte[]> walletRegistrations) {
        this.walletRegistrations = walletRegistrations;
    }

    private record Wallet(SigningPriority signingPriority, ScriptType scriptType, WalletPolicy walletPolicy, Sha256Hash registeredHmac) {}
}
