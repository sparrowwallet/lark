package com.sparrowwallet.lark;

public class SignMessageOperation extends AbstractClientOperation {
    private final String message;
    private final String path;
    private String signature;

    public SignMessageOperation(String deviceType, String message, String path) {
        super(deviceType);
        this.message = message;
        this.path = path;
    }

    public SignMessageOperation(String deviceType, String devicePath, String message, String path) {
        super(deviceType, devicePath);
        this.message = message;
        this.path = path;
    }

    public SignMessageOperation(byte[] fingerprint, String message, String path) {
        super(fingerprint);
        this.message = message;
        this.path = path;
    }

    @Override
    public void apply(HardwareClient hardwareClient) throws DeviceException {
        signature = hardwareClient.signMessage(message, path);
    }

    public String getSignature() {
        return signature;
    }

    @Override
    public boolean success() {
        return signature != null;
    }
}
