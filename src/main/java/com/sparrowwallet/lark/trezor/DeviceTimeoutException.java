package com.sparrowwallet.lark.trezor;

import com.sparrowwallet.lark.DeviceException;

/**
 * Exception thrown when a device communication operation times out.
 * This is a recoverable error for operations that support polling/retry.
 */
public class DeviceTimeoutException extends DeviceException {

    public DeviceTimeoutException(String message) {
        super(message);
    }

    public DeviceTimeoutException(String message, Throwable cause) {
        super(message, cause);
    }
}
