package com.sparrowwallet.lark;

import com.fazecast.jSerialComm.SerialPort;
import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTParseException;
import com.sparrowwallet.drongo.wallet.WalletModel;

import java.util.Base64;
import java.util.List;

/**
 * Lark client for the Banshee hardware wallet (LilyGo T-Display S3).
 */
public class BansheeClient extends HardwareClient {
    public static final List<DeviceId> BANSHEE_DEVICE_IDS = List.of(new DeviceId(0x303a, 0xb05e));

    private final SerialPort serialPort;
    private final String network;
    private String masterFingerprint;

    public BansheeClient(SerialPort serialPort) throws DeviceException {
        if(BANSHEE_DEVICE_IDS.stream().noneMatch(id -> id.matches(serialPort))) {
            throw new DeviceException("Not a Banshee");
        }
        this.serialPort = serialPort;
        this.network = Network.getCanonical();
    }

    @Override
    void initializeMasterFingerprint() throws DeviceException {
        try(BansheeGate gate = new BansheeGate(serialPort, network)) {
            this.masterFingerprint = Utils.bytesToHex(ExtendedKey.fromDescriptor(gate.getXpub("m/0h")).getParentFingerprint());
        }
    }

    @Override
    ExtendedKey getPubKeyAtPath(String path) throws DeviceException {
        try(BansheeGate gate = new BansheeGate(serialPort, network)) {
            return ExtendedKey.fromDescriptor(gate.getXpub(path));
        }
    }

    @Override
    PSBT signTransaction(PSBT psbt) throws DeviceException {
        try(BansheeGate gate = new BansheeGate(serialPort, network)) {
            byte[] psbtBytes = psbt.getForExport().serialize();
            String b64 = Base64.getEncoder().encodeToString(psbtBytes);
            String signedB64 = gate.signPsbt(b64);
            return new PSBT(Base64.getDecoder().decode(signedB64));
        } catch(PSBTParseException e) {
            throw new DeviceException("Invalid signed PSBT from Banshee", e);
        }
    }

    @Override
    String signMessage(String message, String path) throws DeviceException {
        throw new DeviceException("Banshee does not support message signing yet");
    }

    @Override
    String displaySinglesigAddress(String path, ScriptType scriptType) throws DeviceException {
        throw new DeviceException("Banshee does not support address display via host yet");
    }

    @Override
    String displayMultisigAddress(OutputDescriptor outputDescriptor) throws DeviceException {
        throw new DeviceException("Banshee does not support multisig yet");
    }

    @Override
    public String getPath() {
        return serialPort.getSystemPortPath();
    }

    @Override
    public HardwareType getHardwareType() {
        return HardwareType.BANSHEE;
    }

    @Override
    public WalletModel getModel() {
        return WalletModel.BANSHEE;
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
}
