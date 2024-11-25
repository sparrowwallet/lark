package com.sparrowwallet.lark.ledger.command;

public enum DefaultInsType {
    GET_VERSION(0x01);

    private final int value;

    DefaultInsType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
