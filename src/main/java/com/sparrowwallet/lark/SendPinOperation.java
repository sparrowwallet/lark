package com.sparrowwallet.lark;

public class SendPinOperation extends AbstractClientOperation {
    private final String pin;
    private boolean result;

    public SendPinOperation(String deviceType, String pin) {
        super(deviceType);
        this.pin = pin;
    }

    public SendPinOperation(String deviceType, String devicePath, String pin) {
        super(deviceType, devicePath);
        this.pin = pin;
    }

    public SendPinOperation(byte[] fingerprint, String pin) {
        super(fingerprint);
        this.pin = pin;
    }

    @Override
    public void apply(HardwareClient hardwareClient) throws DeviceException {
        result = hardwareClient.sendPin(pin);
    }

    public boolean getResult() {
        return result;
    }
}
