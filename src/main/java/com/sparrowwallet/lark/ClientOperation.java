package com.sparrowwallet.lark;

public interface ClientOperation {
    boolean requires(Interface interfaceType);
    boolean matches(HardwareClient hardwareClient);
    void apply(HardwareClient hardwareClient) throws DeviceException;
}
