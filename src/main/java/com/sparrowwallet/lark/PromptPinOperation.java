package com.sparrowwallet.lark;

public class PromptPinOperation extends AbstractClientOperation {
    private boolean result;

    public PromptPinOperation(String deviceType) {
        super(deviceType);
    }

    public PromptPinOperation(String deviceType, String devicePath) {
        super(deviceType, devicePath);
    }

    public PromptPinOperation(byte[] fingerprint) {
        super(fingerprint);
    }

    @Override
    public void apply(HardwareClient hardwareClient) throws DeviceException {
        result = hardwareClient.promptPin();
    }

    public boolean getResult() {
        return result;
    }
}
