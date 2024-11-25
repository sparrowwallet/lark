package com.sparrowwallet.lark.bitbox02;

import org.hid4java.HidDevice;

public class HidPhysicalLayer implements PhysicalLayer {
    private final HidDevice hidDevice;

    public HidPhysicalLayer(HidDevice hidDevice) {
        this.hidDevice = hidDevice;
    }

    @Override
    public void write(byte[] bytes) {
        hidDevice.write(bytes, bytes.length, (byte)0);
    }

    @Override
    public byte[] read(int size, int timeoutMs) {
        byte[] buffer = new byte[size];
        hidDevice.read(buffer, timeoutMs);
        return buffer;
    }

    @Override
    public void close() {
        hidDevice.close();
    }
}
