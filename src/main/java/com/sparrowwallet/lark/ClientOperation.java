package com.sparrowwallet.lark;

public interface ClientOperation {
    boolean matches(HardwareClient hardwareClient);
    void apply(HardwareClient hardwareClient) throws DeviceException;
}
