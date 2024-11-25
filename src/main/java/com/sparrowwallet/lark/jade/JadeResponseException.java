package com.sparrowwallet.lark.jade;

import com.sparrowwallet.lark.DeviceException;

public class JadeResponseException extends DeviceException {
    private final int code;
    private final String data;

    public JadeResponseException(String message, int code, String data) {
        super(message);
        this.code = code;
        this.data = data;
    }

    public int getCode() {
        return code;
    }

    public String getData() {
        return data;
    }
}
