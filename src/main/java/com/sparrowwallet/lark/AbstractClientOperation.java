package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.wallet.WalletModel;

public abstract class AbstractClientOperation implements ClientOperation {
    private final String deviceType;
    private final String devicePath;
    private final byte[] fingerprint;

    public AbstractClientOperation(String deviceType) {
        this.deviceType = getActualType(deviceType);
        this.devicePath = null;
        this.fingerprint = null;
    }

    public AbstractClientOperation(String deviceType, String devicePath) {
        this.deviceType = getActualType(deviceType);
        this.devicePath = devicePath;
        this.fingerprint = null;
    }

    public AbstractClientOperation(byte[] fingerprint) {
        this.deviceType = null;
        this.devicePath = null;
        this.fingerprint = fingerprint;
    }

    @Override
    public boolean requires(Interface interfaceType) {
        if(deviceType != null) {
            HardwareType hardwareType = HardwareType.fromString(deviceType);
            if(hardwareType != null) {
                return hardwareType.uses(interfaceType);
            }
        }

        return true;
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

    protected static String getActualType(String type) {
        return WalletModel.ONEKEY_PRO.getType().equals(type) ? WalletModel.TREZOR_T.getType() : type;
    }
}
