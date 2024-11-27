package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.psbt.PSBT;

public class SignPsbtOperation extends AbstractClientOperation {
    private PSBT psbt;

    public SignPsbtOperation(String deviceType, PSBT psbt) {
        super(deviceType);
        this.psbt = psbt;
    }

    public SignPsbtOperation(String deviceType, String devicePath, PSBT psbt) {
        super(deviceType, devicePath);
        this.psbt = psbt;
    }

    public SignPsbtOperation(byte[] fingerprint, PSBT psbt) {
        super(fingerprint);
        this.psbt = psbt;
    }

    @Override
    public void apply(HardwareClient hardwareClient) throws DeviceException {
        psbt = hardwareClient.signTransaction(psbt);
    }

    public PSBT getPsbt() {
        return psbt;
    }
}
