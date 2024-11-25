package com.sparrowwallet.lark.trezor;

import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.lark.DeviceId;
import com.sparrowwallet.drongo.Version;

import java.util.List;

public enum TrezorModel {
    T1B1("1", "T1B1", WalletModel.TREZOR_1, new Version("1.8.0"), List.of(new DeviceId(0x534C, 0x0001))),
    T2T1("T", "T2T1", WalletModel.TREZOR_T, new Version("2.1.0"), List.of(new DeviceId(0x1209, 0x53C1), new DeviceId(0x1209, 0x53C0))),
    T2B1("Safe 3", "T2B1", WalletModel.TREZOR_SAFE_3, new Version("2.1.0"), List.of(new DeviceId(0x1209, 0x53C1), new DeviceId(0x1209, 0x53C0))),
    T3T1("Safe 5", "T3T1", WalletModel.TREZOR_SAFE_5, new Version("2.1.0"), List.of(new DeviceId(0x1209, 0x53C1), new DeviceId(0x1209, 0x53C0))),
    T3B1("Safe 3", "T3B1", WalletModel.TREZOR_SAFE_3, new Version("2.1.0"), List.of(new DeviceId(0x1209, 0x53C1), new DeviceId(0x1209, 0x53C0))),
    DISC1("DISC1", "D001", WalletModel.TREZOR_SAFE_5, new Version("2.1.0"), List.of(new DeviceId(0x1209, 0x53C1), new DeviceId(0x1209, 0x53C0))),
    DISC2("DISC2", "D002", WalletModel.TREZOR_SAFE_5, new Version("2.1.0"), List.of(new DeviceId(0x1209, 0x53C1), new DeviceId(0x1209, 0x53C0))),
    KEEPKEY("K1-14M", "keepkey", WalletModel.KEEPKEY, new Version("0.0.0"), List.of());

    private final String name;
    private final String internalName;
    private final WalletModel walletModel;
    private final Version minimumVersion;
    private final List<DeviceId> usbIds;

    TrezorModel(String name, String internalName, WalletModel walletModel, Version minimumVersion, List<DeviceId> usbIds) {
        this.name = name;
        this.internalName = internalName;
        this.walletModel = walletModel;
        this.minimumVersion = minimumVersion;
        this.usbIds = usbIds;
    }

    public String getName() {
        return name;
    }

    public String getInternalName() {
        return internalName;
    }

    public WalletModel getWalletModel() {
        return walletModel;
    }

    public Version getMinimumVersion() {
        return minimumVersion;
    }

    public List<DeviceId> getUsbIds() {
        return usbIds;
    }

    public static TrezorModel fromName(String name) {
        for(TrezorModel model : values()) {
            if(model.name.equals(name)) {
                return model;
            }
        }

        return null;
    }

    public static TrezorModel fromInternalName(String internalName) {
        for(TrezorModel model : values()) {
            if(model.internalName.equals(internalName)) {
                return model;
            }
        }

        return null;
    }
}
