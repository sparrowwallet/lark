package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.ExtendedKey;

public class GetXpubOperation extends AbstractClientOperation {
    private final String path;
    private ExtendedKey xpub;

    public GetXpubOperation(String deviceType, String path) {
        super(deviceType);
        this.path = path;
    }

    public GetXpubOperation(String deviceType, String devicePath, String path) {
        super(deviceType, devicePath);
        this.path = path;
    }

    public GetXpubOperation(byte[] fingerprint, String path) {
        super(fingerprint);
        this.path = path;
    }

    @Override
    public void apply(HardwareClient hardwareClient) throws DeviceException {
        xpub = hardwareClient.getPubKeyAtPath(path);
    }

    public ExtendedKey getXpub() {
        return xpub;
    }

    @Override
    public boolean success() {
        return xpub != null;
    }
}
