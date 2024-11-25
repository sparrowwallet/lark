package com.sparrowwallet.lark.bitbox02;

import com.sparrowwallet.lark.DeviceException;

public class BitBox02Exception extends DeviceException {
    private final int code;

    public BitBox02Exception(String message, int code) {
        super(message);
        this.code = code;
    }

    public int getCode() {
        return code;
    }
}
