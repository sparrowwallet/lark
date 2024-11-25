package com.sparrowwallet.lark.ledger.wallet;

public enum WalletType {
    WALLET_POLICY_V1(1),
    WALLET_POLICY_V2(2);

    private final int version;

    WalletType(int version) {
        this.version = version;
    }

    public int getVersion() {
        return version;
    }
}
