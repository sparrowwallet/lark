package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.OutputDescriptor;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTParseException;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.lark.coldcard.*;
import org.hid4java.HidDevice;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;

import static com.sparrowwallet.lark.coldcard.ColdcardDevice.CKCC_PID;
import static com.sparrowwallet.lark.coldcard.ColdcardDevice.COINKITE_VID;
import static com.sparrowwallet.lark.coldcard.Constants.MAX_BLK_LEN;

public class ColdcardClient extends HardwareClient {
    private static final DeviceId COINKITE_ID = new DeviceId(COINKITE_VID, CKCC_PID);

    private final HidDevice hidDevice;
    private String masterFingerprint;

    public ColdcardClient(HidDevice hidDevice) throws DeviceException {
        if(COINKITE_ID.matches(hidDevice) && hidDevice.getSerialNumber() != null) {
            this.hidDevice = hidDevice;
        } else {
            throw new DeviceException("Not a Coldcard");
        }
    }

    @Override
    void initializeMasterFingerprint() throws DeviceException {
        try(ColdcardDevice coldcardDevice = new ColdcardDevice(hidDevice)) {
            this.masterFingerprint = Utils.bytesToHex(coldcardDevice.getDeviceId().masterFingerprint());
        }
    }

    @Override
    ExtendedKey getPubKeyAtPath(String path) throws DeviceException {
        try(ColdcardDevice coldcardDevice = new ColdcardDevice(hidDevice)) {
            coldcardDevice.checkMitm();
            String rewrittenPath = path.replaceAll("[hH]", "'");
            String resp = (String)coldcardDevice.sendRecv(ProtocolPacker.getXpub(rewrittenPath));
            return ExtendedKey.fromDescriptor(resp);
        }
    }

    @Override
    PSBT signTransaction(PSBT psbt) throws DeviceException {
        try(ColdcardDevice coldcardDevice = new ColdcardDevice(hidDevice)) {
            coldcardDevice.checkMitm();

            String resp = (String)coldcardDevice.sendRecv(ProtocolPacker.getXpub("m/0'"));
            ExtendedKey masterXpub = ExtendedKey.fromDescriptor(resp);
            String masterFingerprint = Utils.bytesToHex(masterXpub.getParentFingerprint());

            int passes = 1;
            for(PSBTInput psbtInput : psbt.getPsbtInputs()) {
                int ourKeys = 0;
                for(Map.Entry<ECKey, KeyDerivation> entry : psbtInput.getDerivedPublicKeys().entrySet()) {
                    if(entry.getValue().getMasterFingerprint().equals(masterFingerprint) && !psbtInput.getPartialSignatures().containsKey(entry.getKey())) {
                        ourKeys++;
                    }

                    if(ourKeys > passes) {
                        passes = ourKeys;
                    }
                }
            }

            PSBT signedPsbt = psbt;
            for(int i = 0; i < passes; i++) {
                byte[] psbtBytes = signedPsbt.getForExport().serialize();
                ByteArrayInputStream bais = new ByteArrayInputStream(psbtBytes);
                int size = psbtBytes.length;

                int left = size;
                MessageDigest digest = Sha256Hash.newDigest();
                for(int pos = 0; pos < size; pos+= MAX_BLK_LEN) {
                    byte[] here = new byte[Math.min(MAX_BLK_LEN, left)];
                    bais.read(here, 0, here.length);
                    left -= here.length;
                    Long uploaded = (Long)coldcardDevice.sendRecv(ProtocolPacker.upload(pos, size, here));
                    if(uploaded != pos) {
                        throw new DeviceException("Upload failed, position " + pos + " != " + uploaded);
                    }
                    digest.update(here);
                }

                Sha256Hash calculated = Sha256Hash.wrap(digest.digest());
                Sha256Hash received = Sha256Hash.wrap((byte[])coldcardDevice.sendRecv(ProtocolPacker.sha256()));
                if(!calculated.equals(received)) {
                    throw new DeviceException("Wrong checksum, expected " + calculated + " but got " + received);
                }

                Object decoded = coldcardDevice.sendRecv(ProtocolPacker.signTransaction(size, calculated.getBytes(), false));
                if(decoded != null) {
                    throw new DeviceException("Received unexpected response of " + decoded);
                }

                Object signResp = null;
                while(signResp == null) {
                    try {
                        Thread.sleep(250);
                    } catch(InterruptedException e) {
                        //ignore
                    }

                    signResp = coldcardDevice.sendRecv(ProtocolPacker.getSignedTxn(), true, -1);
                }

                if(signResp instanceof SignedTransaction signedTx) {
                    byte[] signedBytes = coldcardDevice.downloadFile(signedTx.length(), signedTx.sha256());
                    try {
                        signedPsbt = new PSBT(signedBytes, false);
                    } catch(PSBTParseException e) {
                        throw new DeviceException("Invalid signed PSBT", e);
                    }
                } else {
                    throw new DeviceFailedException("Failed: " + signResp);
                }
            }

            return signedPsbt;
        } catch(DeviceException e) {
            throw e;
        } catch(Exception e) {
            throw new DeviceException("Failed to sign transaction", e);
        }
    }

    @Override
    String signMessage(String message, String path) throws DeviceException {
        try(ColdcardDevice coldcardDevice = new ColdcardDevice(hidDevice)) {
            coldcardDevice.checkMitm();

            Optional<ScriptType> optScriptType = getScriptType(path);
            int addressFormat = optScriptType.isPresent() ? getAddressFormat(optScriptType.get()) : Protocol.AF_CLASSIC;

            String rewrittenPath = path.replaceAll("[hH]", "'");
            byte[] msgBytes = message.getBytes(StandardCharsets.UTF_8);

            Object resp = coldcardDevice.sendRecv(ProtocolPacker.signMessage(msgBytes, rewrittenPath, addressFormat), true, -1);
            if(resp != null) {
                throw new DeviceException("Received unexpected response of " + resp);
            }

            Object result = null;
            while(result == null) {
                try {
                    Thread.sleep(250);
                } catch(InterruptedException e) {
                    //ignore
                }

                result = coldcardDevice.sendRecv(ProtocolPacker.getSignedMessage(), true, -1);
            }

            if(result instanceof SignedMessage signedMessage) {
                return new String(Base64.getEncoder().encode(signedMessage.signature()), StandardCharsets.US_ASCII);
            } else {
                throw new DeviceFailedException("Failed: " + result);
            }
        }
    }

    @Override
    String displaySinglesigAddress(String path, ScriptType scriptType) throws DeviceException {
        try(ColdcardDevice coldcardDevice = new ColdcardDevice(hidDevice)) {
            coldcardDevice.checkMitm();

            String rewrittenPath = path.replaceAll("[hH]", "'");
            int addressFormat = getAddressFormat(scriptType);

            return (String)coldcardDevice.sendRecv(ProtocolPacker.showAddress(rewrittenPath, addressFormat));
        }
    }

    @Override
    String displayMultisigAddress(OutputDescriptor outputDescriptor) throws DeviceException {
        if(!outputDescriptor.isMultisig()) {
            throw new IllegalArgumentException("Output descriptor is not a multisig descriptor: " + outputDescriptor);
        }

        try(ColdcardDevice coldcardDevice = new ColdcardDevice(hidDevice)) {
            coldcardDevice.checkMitm();

            int addressFormat = getAddressFormat(outputDescriptor.getScriptType());
            if(outputDescriptor.getExtendedPublicKeys().isEmpty() || outputDescriptor.getExtendedPublicKeys().size() > 15) {
                throw new IllegalArgumentException("Must provide 1 to 15 keypaths to display a multisig address");
            }

            if(outputDescriptor.getMultisigThreshold() < 1 || outputDescriptor.getMultisigThreshold() > outputDescriptor.getExtendedPublicKeys().size()) {
                throw new IllegalArgumentException("Either the redeem script provided is invalid or the keypaths provided are insufficient");
            }

            List<long[]> xfpPaths = new ArrayList<>();
            for(ExtendedKey extendedKey : outputDescriptor.sortExtendedPubKeys(outputDescriptor.getExtendedPublicKeys())) {
                KeyDerivation keyDerivation = outputDescriptor.getKeyDerivation(extendedKey);
                long[] keyPath = keyDerivation.extend(KeyDerivation.parsePath(outputDescriptor.getChildDerivationPath(extendedKey)))
                        .getDerivation().stream().mapToLong(num -> Integer.toUnsignedLong(num.i())).toArray();
                long[] xfpPath = new long[keyPath.length+1];
                System.arraycopy(keyPath, 0, xfpPath, 1, keyPath.length);
                byte[] mfp = Utils.hexToBytes(keyDerivation.getMasterFingerprint());
                xfpPath[0] = ((long) mfp[0] & 0xFF) | (((long) mfp[1] & 0xFF) << 8) | (((long) mfp[2] & 0xFF) << 16) | (((long) mfp[3] & 0xFF) << 24);;
                xfpPaths.add(xfpPath);
            }

            Collection<ECKey> keys = outputDescriptor.getExtendedPublicKeys().stream().map(extKey -> extKey.getKey(outputDescriptor.getChildDerivation(extKey))).collect(Collectors.toList());
            Script redeemScript = ScriptType.MULTISIG.getOutputScript(outputDescriptor.getMultisigThreshold(), keys);

            byte[] msg = ProtocolPacker.showP2SHAddress((byte)outputDescriptor.getMultisigThreshold(), xfpPaths, redeemScript.getProgram(), addressFormat);
            return (String)coldcardDevice.sendRecv(msg);
        }
    }

    private int getAddressFormat(ScriptType scriptType) throws DeviceException {
        return switch(scriptType) {
            case P2SH_P2WPKH -> Protocol.AF_P2WPKH_P2SH;
            case P2WPKH -> Protocol.AF_P2WPKH;
            case P2PKH -> Protocol.AF_CLASSIC;
            case P2TR -> Protocol.AF_P2TR;
            case P2SH_P2WSH -> Protocol.AF_P2WSH_P2SH;
            case P2WSH -> Protocol.AF_P2WSH;
            case P2SH -> Protocol.AF_P2SH;
            default -> throw new DeviceException("Unsupported script type of " + scriptType);
        };
    }

    @Override
    public String getPath() {
        return hidDevice.getPath();
    }

    @Override
    public HardwareType getHardwareType() {
        return HardwareType.COLDCARD;
    }

    @Override
    public WalletModel getModel() {
        return WalletModel.COLDCARD;
    }

    @Override
    public Boolean needsPinSent() {
        return Boolean.FALSE;
    }

    @Override
    public Boolean needsPassphraseSent() {
        return Boolean.FALSE;
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
}
