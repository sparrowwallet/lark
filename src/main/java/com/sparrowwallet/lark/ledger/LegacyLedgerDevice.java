package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.DeterministicKey;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTOutput;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.Version;
import com.sparrowwallet.lark.ledger.legacy.Btchip;
import com.sparrowwallet.lark.ledger.wallet.WalletPolicy;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.sparrowwallet.lark.HardwareClient.isWitness;

public class LegacyLedgerDevice extends LedgerDevice {
    private final Btchip app;
    private final LedgerVersion version;

    private final List<String> SUPPORTED_POLICIES = List.of("pkh(@0/**)", "pkh(@0/<0;1>/*)", "wpkh(@0/**)", "wpkh(@0/<0;1>/*)", "sh(wpkh(@0/**))", "sh(wpkh(@0/<0;1>/*))");

    public LegacyLedgerDevice(Transport transport, LedgerVersion version) {
        super(transport);
        this.app = new Btchip(transport, version);
        this.version = version;
    }

    @Override
    public String getMasterFingerprint() throws DeviceException {
        Map<String, byte[]> masterPubKey = app.getWalletPublicKey("");
        return Utils.bytesToHex(Arrays.copyOfRange(Utils.sha256hash160(ECKey.fromPublicOnly(masterPubKey.get("publicKey")).getPubKey(true)), 0, 4));
    }

    @Override
    public ExtendedKey getExtendedPubkey(String path, boolean display) throws DeviceException {
        Map<String, byte[]> pubkey = app.getWalletPublicKey(path, display);
        List<ChildNumber> pathElements = KeyDerivation.parsePath(path);
        byte[] parentFingerprint = new byte[4];
        ChildNumber childNumber = ChildNumber.ZERO;
        if(!pathElements.isEmpty()) {
            Map<String, byte[]> parentPubkey = app.getWalletPublicKey(KeyDerivation.writePath(pathElements.subList(0, pathElements.size() - 1)));
            parentFingerprint = Arrays.copyOfRange(Utils.sha256hash160(ECKey.fromPublicOnly(parentPubkey.get("publicKey")).getPubKey(true)), 0, 4);
            childNumber = pathElements.getLast();
        }

        DeterministicKey pubKey = new DeterministicKey(List.of(childNumber), pubkey.get("chainCode"),
                ECKey.fromPublicOnly(pubkey.get("publicKey")).getPubKey(true), pathElements.size(), parentFingerprint);
        return new ExtendedKey(pubKey, parentFingerprint, childNumber);
    }

    @Override
    public List<Signature> signPsbt(PSBT psbt, WalletPolicy walletPolicy, Sha256Hash walletHmac) throws DeviceException {
        if(walletHmac != null || walletPolicy.getNumberOfKeys() != 1) {
            throw new DeviceException("Policy wallets are not supported in the legacy app. Please update your Ledger hardware wallet");
        }

        if(!SUPPORTED_POLICIES.contains(walletPolicy.getDescriptorTemplate())) {
            throw new DeviceException("Unsupported policy");
        }

        Transaction transaction = psbt.getTransaction();
        byte[] transactionBytes = transaction.bitcoinSerialize(true);

        String masterFingerprint = getMasterFingerprint();
        boolean useTrustedSegwit = version.version().compareTo(new Version("1.4.0")) >= 0;

        // NOTE: We only support signing Segwit inputs, where we can skip over non-segwit
        // inputs, or non-segwit inputs, where *all* inputs are non-segwit. This is due
        // to Ledger's mutually exclusive signing steps for each type.

        List<Map<String, Object>> segwitInputs = new ArrayList<>();
        List<Map<String, Object>> legacyInputs = new ArrayList<>();

        boolean hasSegwit = false;
        boolean hasLegacy = false;

        List<Script> scripts = new ArrayList<>();

        // Detect changepath, (p2sh-)p2(w)pkh only
        List<ChildNumber> changePath = new ArrayList<>();
        for(int i = 0; i < transaction.getOutputs().size(); i++) {
            PSBTOutput psbtOutput = psbt.getPsbtOutputs().get(i);
            TransactionOutput output = transaction.getOutputs().get(i);
            // Find which wallet key could be change based on hdsplit: m/.../1/k
            // Wallets shouldn't be sending to change address as user action
            // otherwise this will get confused
            for(ECKey key : psbtOutput.getDerivedPublicKeys().keySet()) {
                KeyDerivation origin = psbtOutput.getDerivedPublicKeys().get(key);
                if(masterFingerprint.equals(origin.getMasterFingerprint()) && origin.getDerivation().size() > 1 &&
                        origin.getDerivation().get(origin.getDerivation().size() - 2).equals(ChildNumber.ONE)) {
                    // For possible matches, check if pubkey matches possible template
                    try {
                        if(Arrays.equals(output.getScript().getPubKeyHash(), key.getPubKeyHash())) {
                            changePath = origin.getDerivation().subList(0, origin.getDerivation().size());
                        }
                    } catch(ProtocolException e) {
                        //ignore
                    }
                }
            }
        }

        Map<Integer, Script> scriptCodes = new HashMap<>();
        Map<Integer, List<Map.Entry<ECKey, KeyDerivation>>> allSignatureAttempts = new HashMap<>();

        for(int i = 0; i < transaction.getInputs().size(); i++) {
            PSBTInput psbtInput = psbt.getPsbtInputs().get(i);
            TransactionInput input = transaction.getInputs().get(i);

            byte[] seqBytes = new byte[4];
            Utils.uint32ToByteArrayLE(input.getSequenceNumber(), seqBytes, 0);
            String seqHex = Utils.bytesToHex(seqBytes);

            Script script;
            TransactionOutput utxo = null;
            if(psbtInput.getWitnessUtxo() != null) {
                utxo = psbtInput.getWitnessUtxo();
            }
            if(psbtInput.getNonWitnessUtxo() != null) {
                utxo = psbtInput.getNonWitnessUtxo().getOutputs().get(psbtInput.getPrevIndex().intValue());
            }
            if(utxo == null) {
                throw new DeviceException("PSBT is missing input utxo information, cannot sign");
            }
            script = utxo.getScript();

            if(ScriptType.P2SH.isScriptType(script)) {
                if(psbtInput.getRedeemScript() == null) {
                    continue;
                }
                script = psbtInput.getRedeemScript();
            }

            Optional<ScriptType> optWitnessType = isWitness(script);

            byte[] valueBytes = new byte[8];
            Utils.int64ToByteArrayLE(utxo.getValue(), valueBytes, 0);
            segwitInputs.add(new HashMap<>(Map.of("value", Utils.concat(input.getOutpoint().bitcoinSerialize(), valueBytes), "witness", Boolean.TRUE, "sequence", seqHex)));
            if(optWitnessType.isPresent()) {
                if(ScriptType.P2WSH.isScriptType(script)) {
                    if(psbtInput.getWitnessScript() == null) {
                        continue;
                    }
                    script = psbtInput.getWitnessScript();
                } else if(ScriptType.P2WPKH.isScriptType(script)) {
                    byte[] witnessProgram = ScriptType.P2WPKH.getHashFromScript(script);
                    ByteBuffer buffer = ByteBuffer.allocate(3 + witnessProgram.length + 2);
                    buffer.put(new byte[] { 0x76, (byte)0xA9, 0x14 });
                    buffer.put(witnessProgram);
                    buffer.put(new byte[] { (byte)0x88, (byte)0xAC });
                    script = new Script(buffer.array());
                } else {
                    continue;
                }
                hasSegwit = true;
            } else {
                // We only need legacy inputs in the case where all inputs are legacy, we check later
                if(psbtInput.getNonWitnessUtxo() == null) {
                    throw new DeviceException("Non witness UTXO cannot be null");
                }
                legacyInputs.add(app.getTrustedInput(psbtInput.getNonWitnessUtxo(), psbtInput.getPrevIndex()));
                legacyInputs.getLast().put("sequence", seqHex);
                hasLegacy = true;
            }

            if(psbtInput.getNonWitnessUtxo() != null && useTrustedSegwit) {
                segwitInputs.getLast().putAll(app.getTrustedInput(psbtInput.getNonWitnessUtxo(), psbtInput.getPrevIndex()));
            }

            Set<ECKey> pubKeys = new HashSet<>();
            List<Map.Entry<ECKey, KeyDerivation>> signatureAttempts = new ArrayList<>();

            // Save scriptcode for later signing
            scriptCodes.put(i, script);

            // Find which pubkeys could sign this input (should be all?)
            for(ECKey key : psbtInput.getDerivedPublicKeys().keySet()) {
                try {
                    if(Arrays.equals(script.getPubKeyHash(), key.getPubKeyHash())) {
                        pubKeys.add(key);
                    }
                } catch(ProtocolException e) {
                    //ignore
                }
                try {
                    if(key.equals(script.getPubKey())) {
                        pubKeys.add(key);
                    }
                } catch(ProtocolException e) {
                    //ignore
                }
                if(ScriptType.MULTISIG.isScriptType(script)) {
                    pubKeys.addAll(Arrays.asList(ScriptType.MULTISIG.getPublicKeysFromScript(script)));
                }
            }

            // Figure out which keys in inputs are from our wallet
            for(ECKey pubKey : pubKeys) {
                KeyDerivation keypath = psbtInput.getDerivedPublicKeys().get(pubKey);
                if(masterFingerprint.equals(keypath.getMasterFingerprint())) {
                    // Add the keypaths
                    signatureAttempts.add(Map.entry(pubKey, keypath));
                }
            }

            allSignatureAttempts.put(i, signatureAttempts);
        }

        List<Signature> results = new ArrayList<>();

        // Sign any segwit inputs
        if(hasSegwit) {
            // Process them up front with all scriptcodes blank
            Script blankScript = new Script(new byte[0]);
            for(int i = 0; i < segwitInputs.size(); i++) {
                app.startUntrustedTransaction(i == 0, i, segwitInputs, useTrustedSegwit ? scriptCodes.get(i) : blankScript, transaction.getVersion());
            }

            // Number of unused fields for Nano S, only changepath and transaction in bytes req
            app.finalizeInput("DUMMY".getBytes(StandardCharsets.UTF_8), -1, -1, changePath, transaction);

            // For each input we control do segwit signature
            for(int i = 0; i < segwitInputs.size(); i++) {
                for(Map.Entry<ECKey, KeyDerivation> signatureAttempt : allSignatureAttempts.get(i)) {
                    app.startUntrustedTransaction(false, 0, List.of(segwitInputs.get(i)), scriptCodes.get(i), transaction.getVersion());

                    byte[] signatureBytes = app.untrustedHashSign(signatureAttempt.getValue().getDerivationPath(), "", transaction.getLocktime(), SigHash.ALL);
                    TransactionSignature signature = TransactionSignature.decodeFromBitcoin(signatureBytes, false);

                    results.add(new Signature(i, signatureAttempt.getKey(), signature));
                }
            }
        } else if(hasLegacy) {
            boolean firstInput = true;
            for(int i = 0; i < legacyInputs.size(); i++) {
                for(Map.Entry<ECKey, KeyDerivation> signatureAttempt : allSignatureAttempts.get(i)) {
                    if(psbt.getPsbtInputs().get(i).getNonWitnessUtxo() == null) {
                        throw new DeviceException("Non witness UTXO cannot be null");
                    }
                    app.startUntrustedTransaction(firstInput, i, legacyInputs, scriptCodes.get(i), transaction.getVersion());
                    app.finalizeInput("DUMMY".getBytes(StandardCharsets.UTF_8), -1, -1, changePath, transaction);

                    byte[] signatureBytes = app.untrustedHashSign(signatureAttempt.getValue().getDerivationPath(), "", transaction.getLocktime(), SigHash.ALL);
                    TransactionSignature signature = TransactionSignature.decodeFromBitcoin(signatureBytes, false);

                    results.add(new Signature(i, signatureAttempt.getKey(), signature));
                    firstInput = false;
                }
            }
        }

        return results;
    }

    @Override
    public WalletRegistration registerWallet(WalletPolicy walletPolicy) throws DeviceException {
        throw new UnsupportedOperationException("The Ledger legacy app does not have this functionality");
    }

    @Override
    public String signMessage(String message, String path) throws DeviceException {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        // First display on screen what address you're signing for
        app.getWalletPublicKey(path, true);
        app.signMessagePrepare(path, messageBytes);
        byte[] signature = app.signMessageSign();

        int rLength = signature[3];
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 4, 4 + rLength));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 4 + rLength + 2, signature.length));

        ByteBuffer buf = ByteBuffer.allocate(65);
        buf.put((byte)(27 + 4 + (signature[0] & 0x01)));
        buf.put(Utils.bigIntegerToBytes(r, 32));
        buf.put(Utils.bigIntegerToBytes(s, 32));

        return Base64.getEncoder().encodeToString(buf.array());
    }

    @Override
    public String getWalletAddress(WalletPolicy walletPolicy, Sha256Hash walletHmac, int change, int addressIndex, boolean display) throws DeviceException {
        if(walletHmac != null || walletPolicy.getNumberOfKeys() != 1) {
            throw new DeviceException("Policy wallets are not supported in the legacy app. Please update your Ledger hardware wallet");
        }

        String keyInfo = walletPolicy.getKeysInfo().getFirst();
        int firstSlashPos = keyInfo.indexOf('/');
        int keyOriginEnd = keyInfo.indexOf(']');
        if(firstSlashPos == -1 || keyOriginEnd == -1) {
            throw new IllegalArgumentException("Could not extract key origin information");
        }

        if(keyInfo.charAt(0) != '[') {
            throw new IllegalArgumentException("Key must have key origin information");
        }

        String keyOriginPath = keyInfo.substring(firstSlashPos + 1, keyOriginEnd);
        ScriptType scriptType = getScriptTypeForWalletPolicy(walletPolicy);

        boolean p2shP2wpkh = scriptType == ScriptType.P2SH_P2WPKH;
        boolean bech32 = scriptType == ScriptType.P2WPKH;
        Map<String, byte[]> output = app.getWalletPublicKey(keyOriginPath, display, p2shP2wpkh || bech32, bech32, false);
        byte[] addressBytes = output.get("address");

        return new String(addressBytes, StandardCharsets.UTF_8);
    }

    private ScriptType getScriptTypeForWalletPolicy(WalletPolicy walletPolicy) {
        return switch(walletPolicy.getDescriptorTemplate()) {
            case "pkh(@0/**)" -> ScriptType.P2PKH;
            case "wpkh(@0/**)" -> ScriptType.P2WPKH;
            case "sh(wpkh(@0/**))" -> ScriptType.P2SH_P2WPKH;
            default -> throw new IllegalArgumentException("Invalid or unsupported policy");
        };
    }
}
