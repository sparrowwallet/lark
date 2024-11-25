package com.sparrowwallet.lark.ledger;

import java.util.Arrays;

public class APDUResponse {
    private final byte[] apdu;

    public APDUResponse(byte[] apdu) {
        this.apdu = apdu.clone();
        if(apdu.length < 2) {
            throw new IllegalArgumentException("apdu must be at least 2 bytes long");
        }
    }

    public int getSW1() {
        return apdu[apdu.length - 2] & 0xff;
    }

    public int getSW2() {
        return apdu[apdu.length - 1] & 0xff;
    }

    public int getSW() {
        return (getSW1() << 8) | getSW2();
    }

    public int getNr() {
        return apdu.length - 2;
    }

    public byte[] getBytes() {
        return apdu.clone();
    }

    public byte[] getData() {
        if(apdu.length == 2) {
            return new byte[0];
        }
        return Arrays.copyOfRange(apdu, 0, getNr());
    }

    public byte[] getDataRange(int from, int to) {
        if(from < 0 || from > getNr() || to < 0 || to > getNr() || from > to) {
            throw new IllegalArgumentException();
        }
        return Arrays.copyOfRange(apdu, from, to);
    }

    public byte getDataByte(int index) {
        if(index < 0 || index > getNr()) {
            throw new IndexOutOfBoundsException("Index " + index + " out of bounds for length " + getNr());
        }
        return apdu[index];
    }
}
