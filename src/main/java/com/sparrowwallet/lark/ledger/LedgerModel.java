package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.lark.DeviceId;

import java.util.ArrayList;
import java.util.List;

public enum LedgerModel {
    LEDGER_NANO_S(0x10, "ledger_nano_s", WalletModel.LEDGER_NANO_S),
    LEDGER_NANO_X(0x40, "ledger_nano_x", WalletModel.LEDGER_NANO_X),
    LEDGER_NANO_S_PLUS(0x50, "ledger_nano_s_plus", WalletModel.LEDGER_NANO_S_PLUS),
    LEDGER_STAX(0x60, "ledger_stax", WalletModel.LEDGER_STAX),
    LEDGER_FLEX(0x70, "ledger_flex", WalletModel.LEDGER_FLEX),
    LEDGER_NANO_GEN5(0x80, "ledger_nano_gen5", WalletModel.LEDGER_NANO_GEN5),
    LEGACY_LEDGER_NANO_S(0x0001, "ledger_nano_s", WalletModel.LEDGER_NANO_S),
    LEGACY_LEDGER_NANO_X(0x0004, "ledger_nano_x", WalletModel.LEDGER_NANO_X);

    private final int modelId;
    private final String name;
    private final WalletModel walletModel;

    private static final int VENDOR_ID = 0x2c97;

    LedgerModel(int modelId, String name, WalletModel walletModel) {
        this.modelId = modelId;
        this.name = name;
        this.walletModel = walletModel;
    }

    public int getModelId() {
        return modelId;
    }

    public String getName() {
        return name;
    }

    public WalletModel getWalletModel() {
        return walletModel;
    }

    public static List<DeviceId> getDeviceIds() {
        List<DeviceId> deviceIds = new ArrayList<>();
        for(LedgerModel ledgerModel : values()) {
            deviceIds.add(new DeviceId(VENDOR_ID, ledgerModel.getModelId()));
        }

        return deviceIds;
    }

    public static LedgerModel getLedgerModel(int modelId) {
        for(LedgerModel ledgerModel : values()) {
            if(ledgerModel.getModelId() == modelId) {
                return ledgerModel;
            }
        }

        throw new IllegalArgumentException("Unknown ledger model: " + modelId);
    }
}
