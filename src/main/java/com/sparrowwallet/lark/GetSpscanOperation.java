package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.silentpayments.SilentPaymentScanAddress;

public class GetSpscanOperation extends AbstractClientOperation {
    private final String path;
    private SilentPaymentScanAddress spscan;

    public GetSpscanOperation(String deviceType, String path) {
        super(deviceType);
        this.path = path;
    }

    public GetSpscanOperation(String deviceType, String devicePath, String path) {
        super(deviceType, devicePath);
        this.path = path;
    }

    public GetSpscanOperation(byte[] fingerprint, String path) {
        super(fingerprint);
        this.path = path;
    }

    @Override
    public void apply(HardwareClient hardwareClient) throws DeviceException {
        spscan = hardwareClient.getSpscanAtPath(path);
    }

    public SilentPaymentScanAddress getSpscan() {
        return spscan;
    }

    @Override
    public boolean success() {
        return spscan != null;
    }
}
