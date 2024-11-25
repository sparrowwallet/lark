package com.sparrowwallet.lark.ledger;

import java.util.Arrays;

public class APDUCommand {

    private final byte[] apdu;
    private final int nc;

    public APDUCommand(int cla, int ins, int p1, int p2) {
        this(cla, ins, p1, p2, false);
    }

    public APDUCommand(int cla, int ins, int p1, int p2, boolean ncAnyways) {
        apdu = new byte[ncAnyways ? 5 : 4];
        apdu[0] = (byte) cla;
        apdu[1] = (byte) ins;
        apdu[2] = (byte) p1;
        apdu[3] = (byte) p2;
        nc = 0;
        if(ncAnyways) {
            apdu[4] = 0;
        }
    }

    public APDUCommand(int cla, int ins, int p1, int p2, byte[] data) {
        apdu = new byte[5 + data.length];
        apdu[0] = (byte) cla;
        apdu[1] = (byte) ins;
        apdu[2] = (byte) p1;
        apdu[3] = (byte) p2;
        nc = data.length;
        apdu[4] = (byte) nc;
        System.arraycopy(data, 0, apdu, 5, data.length);
    }

    public int getCLA() {
        return apdu[0] & 0xFF;
    }

    public int getINS() {
        return apdu[1] & 0xFF;
    }

    public int getP1() {
        return apdu[2] & 0xFF;
    }

    public int getP2() {
        return apdu[3] & 0xFF;
    }

    public int getNc() {
        return nc;
    }

    public byte[] getBytes() {
        return apdu.clone();
    }

    public byte[] getData() {
        if(nc == 0) {
            return new byte[0];
        }
        return Arrays.copyOfRange(apdu, 5, apdu.length);
    }

    public byte getDataByte(int index) {
        if(index < 0 || index > apdu.length - 5) {
            throw new IndexOutOfBoundsException("Index " + index + " out of bounds for length " + (apdu.length - 5));
        }
        return apdu[5 + index];
    }
}
