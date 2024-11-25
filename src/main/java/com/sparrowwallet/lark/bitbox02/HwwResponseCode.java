package com.sparrowwallet.lark.bitbox02;

public enum HwwResponseCode {
    RSP_ACK(new byte[] {0x00}), RSP_NOT_READY(new byte[] { 0x01 }), RSP_BUSY(new byte[] { 0x02 }), RSP_NACK(new byte[] { 0x03 });

    private final byte[] code;

    HwwResponseCode(byte[] code) {
        this.code = code;
    }

    public byte[] getCode() {
        return code;
    }
}
