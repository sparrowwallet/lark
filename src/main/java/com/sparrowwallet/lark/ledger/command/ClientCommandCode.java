package com.sparrowwallet.lark.ledger.command;

public enum ClientCommandCode {
    YIELD(0x10),
    GET_PREIMAGE(0x40),
    GET_MERKLE_LEAF_PROOF(0x41),
    GET_MERKLE_LEAF_INDEX(0x42),
    GET_MORE_ELEMENTS(0xA0);

    private final int code;

    ClientCommandCode(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }
}
