package com.sparrowwallet.lark.ledger.command;

public enum BitcoinInsType {
    GET_EXTENDED_PUBKEY(0x00),
    GET_ADDRESS(0x01),
    REGISTER_WALLET(0x02),
    GET_WALLET_ADDRESS(0x03),
    SIGN_PSBT(0x04),
    GET_MASTER_FINGERPRINT(0x05),
    SIGN_MESSAGE(0x10);

    private final int value;

    BitcoinInsType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
