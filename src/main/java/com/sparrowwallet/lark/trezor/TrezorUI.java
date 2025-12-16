package com.sparrowwallet.lark.trezor;

import com.sparrowwallet.lark.DeviceException;

public interface TrezorUI {
    /**
     * Called when device requests button confirmation.
     * @param code Button request code (type of confirmation)
     */
    void buttonRequest(Integer code);

    /**
     * Request PIN from user.
     * @param code PIN type code
     * @return PIN entered by user
     * @throws DeviceException if user cancels or error occurs
     */
    String getPin(Integer code) throws DeviceException;

    /**
     * Notify that passphrase entry is not allowed.
     */
    void disallowPassphrase();

    /**
     * Request passphrase from user.
     * @param availableOnDevice true if device can accept passphrase
     * @return Passphrase string or TrezorDevice.PASSPHRASE_ON_DEVICE constant
     * @throws DeviceException if user cancels or error occurs
     */
    Object getPassphrase(boolean availableOnDevice) throws DeviceException;
}
