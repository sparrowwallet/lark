package com.sparrowwallet.lark;

public class DeviceInitializationException extends DeviceException {
    public DeviceInitializationException(String message) {
        super(message);
    }

    public DeviceInitializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
