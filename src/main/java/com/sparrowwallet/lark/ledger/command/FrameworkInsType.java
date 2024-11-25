package com.sparrowwallet.lark.ledger.command;

public enum FrameworkInsType {
    CONTINUE_INTERRUPTED(0x01);

    private final int value;

    FrameworkInsType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
