package com.sparrowwallet.lark.trezor;

import com.sparrowwallet.lark.DeviceException;

public interface TrezorUI {
    void buttonRequest(Integer code);
    String getPin(Integer code) throws DeviceException;
    void disallowPassphrase();
    Object getPassphrase(boolean availableOnDevice) throws DeviceException;
}
