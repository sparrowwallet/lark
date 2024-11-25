package com.sparrowwallet.lark;

import com.fazecast.jSerialComm.SerialPort;
import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.OutputDescriptor;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTParseException;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.lark.jade.JadeDevice;
import com.sparrowwallet.lark.jade.JadeVersion;

import java.util.List;

public class JadeClient extends HardwareClient {
    public static final List<DeviceId> JADE_DEVICE_IDS = List.of(new DeviceId(0x10c4, 0xea60),
            new DeviceId(0x1a86, 0x55d4), new DeviceId(0x0403, 0x6001), new DeviceId(0x1a86, 0x7523),
            new DeviceId(0x303a, 0x4001), new DeviceId(0x303a, 0x1001));
    private static final Version MIN_SUPPORTED_VERSION = new Version("0.1.47");

    private final SerialPort serialPort;
    private String masterFingerprint;

    public JadeClient(SerialPort serialPort) throws DeviceException {
        if(JADE_DEVICE_IDS.stream().anyMatch(deviceId -> deviceId.matches(serialPort))) {
            this.serialPort = serialPort;
        } else {
            throw new DeviceException("Not a Jade");
        }
    }

    @Override
    void initializeMasterFingerprint() throws DeviceException {
        try(JadeDevice jadeDevice = new JadeDevice(serialPort)) {
            initialize(jadeDevice);
            this.masterFingerprint = Utils.bytesToHex(jadeDevice.getXpub(Network.get(), "m/0h").getParentFingerprint());
        }
    }

    @Override
    ExtendedKey getPubKeyAtPath(String path) throws DeviceException {
        try(JadeDevice jadeDevice = new JadeDevice(serialPort)) {
            initialize(jadeDevice);
            return jadeDevice.getXpub(Network.get(), path);
        }
    }

    @Override
    PSBT signTransaction(PSBT psbt) throws DeviceException {
        try(JadeDevice jadeDevice = new JadeDevice(serialPort)) {
            initialize(jadeDevice);
            byte[] psbtBytes = psbt.serialize();
            byte[] signedPsbtBytes = jadeDevice.signTransaction(Network.get(), psbtBytes);
            return new PSBT(signedPsbtBytes);
        } catch(PSBTParseException e) {
            throw new DeviceException("Invalid signed PSBT", e);
        }
    }

    @Override
    String signMessage(String message, String path) throws DeviceException {
        try(JadeDevice jadeDevice = new JadeDevice(serialPort)) {
            initialize(jadeDevice);
            return jadeDevice.signMessage(message, path);
        }
    }

    @Override
    String displaySinglesigAddress(String path, ScriptType scriptType) throws DeviceException {
        try(JadeDevice jadeDevice = new JadeDevice(serialPort)) {
            initialize(jadeDevice);
            return jadeDevice.displaySinglesigAddress(Network.get(), path, scriptType);
        }
    }

    @Override
    String displayMultisigAddress(OutputDescriptor outputDescriptor) throws DeviceException {
        try(JadeDevice jadeDevice = new JadeDevice(serialPort)) {
            initialize(jadeDevice);
            String name = getWalletNameOrDefault(outputDescriptor);
            jadeDevice.registerMultisig(Network.get(), name, outputDescriptor);
            return jadeDevice.displayMultisigAddress(Network.get(), name, outputDescriptor);
        }
    }

    private void initialize(JadeDevice jadeDevice) throws DeviceException {
        JadeVersion jadeVersion = jadeDevice.getVersionInfo();
        if(jadeVersion.JADE_VERSION().compareTo(MIN_SUPPORTED_VERSION) < 0) {
            throw new DeviceException("Jade fw version: " + jadeVersion.JADE_VERSION() + " < minimum required version: " + MIN_SUPPORTED_VERSION);
        }

        jadeDevice.addEntropy();

        boolean authenticated = false;
        while(!authenticated) {
            authenticated = jadeDevice.authUser(Network.get());
        }
    }

    @Override
    public String getPath() {
        return serialPort.getSystemPortPath();
    }

    @Override
    public HardwareType getHardwareType() {
        return HardwareType.JADE;
    }

    @Override
    public WalletModel getModel() {
        return WalletModel.JADE;
    }

    @Override
    public Boolean needsPinSent() {
        return null;
    }

    @Override
    public Boolean needsPassphraseSent() {
        return null;
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

    @Override
    public final boolean equals(Object o) {
        if(this == o) {
            return true;
        }
        if(!(o instanceof JadeClient that)) {
            return false;
        }

        return getModel().equals(that.getModel());
    }

    @Override
    public int hashCode() {
        return getModel().hashCode();
    }
}
