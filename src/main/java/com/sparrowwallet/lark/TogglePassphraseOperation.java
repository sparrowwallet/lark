package com.sparrowwallet.lark;

public class TogglePassphraseOperation extends AbstractClientOperation {
    private Boolean result;

    public TogglePassphraseOperation(String deviceType) {
        super(deviceType);
    }

    public TogglePassphraseOperation(String deviceType, String devicePath) {
        super(deviceType, devicePath);
    }

    public TogglePassphraseOperation(byte[] fingerprint) {
        super(fingerprint);
    }

    @Override
    public void apply(HardwareClient hardwareClient) throws DeviceException {
        result = hardwareClient.togglePassphrase();
    }

    public boolean getResult() {
        return result != null && result;
    }

    @Override
    public boolean success() {
        return result != null;
    }
}
