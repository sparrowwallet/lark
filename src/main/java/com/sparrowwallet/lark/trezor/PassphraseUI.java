package com.sparrowwallet.lark.trezor;

import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.Lark;

import static com.sparrowwallet.lark.trezor.TrezorDevice.PASSPHRASE_ON_DEVICE;

public class PassphraseUI implements TrezorUI {
    private String passphrase;
    private boolean pinMatrixShown;
    private boolean promptShown;
    private boolean alwaysPrompt;
    private boolean returnPassphrase;

    public PassphraseUI(String passphrase) {
        this.passphrase = passphrase;
        this.returnPassphrase = true;
    }

    @Override
    public void buttonRequest(Integer code) {
        if(Lark.isConsoleOutput() && !promptShown) {
            System.out.println("Please confirm action on your Trezor device");
        }
        if(!alwaysPrompt) {
            promptShown = true;
        }
    }

    @Override
    public String getPin(Integer code) throws DeviceException {
        throw new UnsupportedOperationException("getPin is not needed");
    }

    @Override
    public void disallowPassphrase() {
        this.returnPassphrase = false;
    }

    @Override
    public Object getPassphrase(boolean availableOnDevice) throws DeviceException {
        if(availableOnDevice) {
            return PASSPHRASE_ON_DEVICE;
        }
        if(returnPassphrase) {
            return passphrase;
        }

        throw new DeviceException("Passphrase from Host is not allowed for Trezor T");
    }
}
