package com.sparrowwallet.lark;

public class InitializeFingerprintOperation extends EnumerateOperation {
    @Override
    public void apply(HardwareClient hardwareClient) throws DeviceException {
        super.apply(hardwareClient);
        hardwareClient.initializeMasterFingerprint();
    }
}
