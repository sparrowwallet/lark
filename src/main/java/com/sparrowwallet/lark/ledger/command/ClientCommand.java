package com.sparrowwallet.lark.ledger.command;

import com.sparrowwallet.lark.DeviceException;

public interface ClientCommand {
    byte[] execute(byte[] request) throws DeviceException;
    int code();
}
