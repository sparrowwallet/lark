package com.sparrowwallet.lark.ledger;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class ByteStreamParser {
    private final ByteArrayInputStream stream;

    public ByteStreamParser(byte[] input) {
        this.stream = new ByteArrayInputStream(input);
    }

    public void assertEmpty() throws IOException {
        if(stream.available() > 0) {
            throw new IOException("Byte stream was expected to be empty");
        }
    }

    public byte[] readBytes(int n) throws IOException {
        byte[] result = new byte[n];
        int bytesRead = stream.read(result);
        if(bytesRead < n) {
            throw new EOFException("Byte stream exhausted");
        }
        return result;
    }

    public byte[] readRemaining() throws IOException {
        byte[] result = new byte[stream.available()];
        stream.read(result);
        return result;
    }

    public long readUint(int n, ByteOrder byteOrder) throws IOException {
        byte[] bytes = readBytes(n);
        ByteBuffer buffer = ByteBuffer.wrap(bytes).order(byteOrder);

        return switch(n) {
            case 1 -> buffer.get() & 0xFF;
            case 2 -> buffer.getShort() & 0xFFFF;
            case 4 -> buffer.getInt() & 0xFFFFFFFFL;
            case 8 -> buffer.getLong();
            default -> throw new IllegalArgumentException("Unsupported byte length: " + n);
        };
    }

    public long readVarint() throws IOException {
        int prefix = (int)readUint(1, ByteOrder.BIG_ENDIAN);

        return switch(prefix) {
            case 253 -> readUint(2, ByteOrder.LITTLE_ENDIAN);
            case 254 -> readUint(4, ByteOrder.LITTLE_ENDIAN);
            case 255 -> readUint(8, ByteOrder.LITTLE_ENDIAN);
            default -> prefix;
        };
    }
}
