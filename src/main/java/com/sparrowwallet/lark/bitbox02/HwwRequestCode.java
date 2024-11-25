package com.sparrowwallet.lark.bitbox02;

public enum HwwRequestCode {
    REQ_NEW(new byte[] {0x00}), REQ_RETRY(new byte[] { 0x01 }), REQ_CANCEL(new byte[] { 0x02 }), REQ_INFO(new byte[] { 'i' });

    private final byte[] code;

    HwwRequestCode(byte[] code) {
        this.code = code;
    }

    public byte[] getCode() {
        return code;
    }
}
