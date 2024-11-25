package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.lark.DeviceException;

import java.io.Closeable;

public interface Transport extends Closeable {
    void open();
    int send(byte[] data);
    Transport.Response recv() throws DeviceException;
    Transport.Response exchange(byte[] data) throws DeviceException;
    Transport.Response apduExchange(APDUCommand apduCommand) throws DeviceException;

    public record Response(int sw, byte[] data) {
        String swCode() {
            return "0x" + Integer.toHexString(sw);
        }
    }
}
