package com.sparrowwallet.lark;

public class DeviceBusyException extends DeviceException {
    public DeviceBusyException() {
        super("Device is busy");
    }
}
