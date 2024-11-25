package com.sparrowwallet.lark;

public class UserRefusedException extends DeviceException {
    public UserRefusedException() {
        super("User refused action");
    }

    public UserRefusedException(String message) {
        super(message);
    }
}
