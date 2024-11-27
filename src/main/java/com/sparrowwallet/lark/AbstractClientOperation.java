package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.Utils;

public abstract class AbstractClientOperation implements ClientOperation {
    private final String deviceType;
    private final String devicePath;
    private final byte[] fingerprint;

    public AbstractClientOperation(String deviceType) {
        this.deviceType = deviceType;
        this.devicePath = null;
        this.fingerprint = null;
    }

    public AbstractClientOperation(String deviceType, String devicePath) {
        this.deviceType = deviceType;
        this.devicePath = devicePath;
        this.fingerprint = null;
    }

    public AbstractClientOperation(byte[] fingerprint) {
        this.deviceType = null;
        this.devicePath = null;
        this.fingerprint = fingerprint;
    }

    @Override
    public boolean matches(HardwareClient client) {
        if(deviceType != null && devicePath != null) {
            return client.getType().equals(deviceType) && client.getPath().equals(devicePath);
        }
        if(deviceType != null) {
            return client.getType().equals(deviceType);
        }
        if(fingerprint != null) {
            return client.fingerprint().equals(Utils.bytesToHex(fingerprint));
        }
        return false;
    }
}
