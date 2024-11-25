package com.sparrowwallet.lark;

public class DeviceFailedException extends DeviceException {
    public DeviceFailedException(String message) {
        super(message);
    }

    public DeviceFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
