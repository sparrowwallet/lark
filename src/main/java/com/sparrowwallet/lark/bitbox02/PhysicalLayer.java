package com.sparrowwallet.lark.bitbox02;

public interface PhysicalLayer {
    void write(byte[] bytes);
    byte[] read(int size, int timeoutMs);
    void close();
}
