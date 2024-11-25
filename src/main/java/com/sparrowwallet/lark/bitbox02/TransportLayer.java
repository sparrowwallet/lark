package com.sparrowwallet.lark.bitbox02;

import com.sparrowwallet.lark.DeviceException;

public abstract class TransportLayer {
    public abstract void write(byte[] bytes, int endpoint, long cid) throws DeviceException;
    public abstract byte[] read(int endpoint, long cid) throws DeviceException;
    public byte[] query(byte[] bytes, int endpoint, long cid) throws DeviceException {
        write(bytes, endpoint, cid);
        return read(endpoint, cid);
    }
    public abstract long generateCid();
    public abstract void close();
}
