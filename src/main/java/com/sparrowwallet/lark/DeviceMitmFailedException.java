package com.sparrowwallet.lark;

public class DeviceMitmFailedException extends DeviceException {
    public DeviceMitmFailedException(String message) {
        super(message);
    }

    public DeviceMitmFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
