package com.sparrowwallet.lark.bitbox02;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.lark.DeviceException;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

public class U2FHid extends TransportLayer {
    private final PhysicalLayer device;

    public static final int USB_REPORT_SIZE = 64;

    private static final int ERR_NONE = 0x00;
    private static final int ERR_INVALID_CMD = 0x01;
    private static final int ERR_INVALID_PAR = 0x02;
    private static final int ERR_INVALID_LEN = 0x03;
    private static final int ERR_INVALID_SEQ = 0x04;
    private static final int ERR_MSG_TIMEOUT = 0x05;
    private static final int ERR_CHANNEL_BUSY = 0x06;
    private static final int ERR_LOCK_REQUIRED = 0x0A;
    private static final int ERR_INVALID_CID = 0x0B;
    private static final int ERR_ENCRYPTION_FAILED = 0x7E;
    private static final int ERR_OTHER = 0x7F;

    private static final int PING = ((byte)0x80 | 0x01) & 0xFF;
    private static final int MSG = ((byte)0x80 | 0x03) & 0xFF;
    private static final int LOCK = ((byte)0x80 | 0x04) & 0xFF;
    private static final int INIT = ((byte)0x80 | 0x06) & 0xFF;
    private static final int WINK = ((byte)0x80 | 0x08) & 0xFF;
    private static final int SYNC = ((byte)0x80 | 0x3C) & 0xFF;
    private static final int ERROR = ((byte)0x80 | 0x3F) & 0xFF;

    public U2FHid(PhysicalLayer device) {
        this.device = device;
    }

    public long generateCid() {
        Random random = new Random();
        return random.nextLong(1, 0xFFFFFFFFL);
    }

    public void throwException(int errorCode) throws DeviceException {
        switch(errorCode) {
            case ERR_INVALID_CMD -> throw new DeviceException("Received error: invalid command");
            case ERR_INVALID_LEN -> throw new DeviceException("Received error: invalid length");
            case ERR_INVALID_SEQ -> throw new DeviceException("Received error: invalid sequence");
            case ERR_MSG_TIMEOUT -> throw new DeviceException("Received error: message timeout");
            case ERR_CHANNEL_BUSY -> throw new DeviceException("Received error: channel busy");
            case ERR_LOCK_REQUIRED -> throw new DeviceException("Received error: lock required");
            case ERR_INVALID_CID -> throw new DeviceException("Received error: invalid channel ID");
            case ERR_ENCRYPTION_FAILED -> throw new DeviceException("Received error: encryption failed");
            case ERR_OTHER -> throw new DeviceException("Received error: other");
            default -> throw new DeviceException("Received error: " + errorCode);
        }
    }

    public void write(byte[] bytes, int endpoint, long cid) throws DeviceException {
        if(endpoint < 0 || endpoint > 0xFF) {
            throw new DeviceException("Channel command (endpoint) is out of range '0 < endpoint <= 0xFF'");
        }
        if(cid < 0 || cid > 0xFFFFFFFFL) {
            throw new DeviceException("Channel id is out of range '0 < cid <= 0xFFFFFFFF'");
        }
        int dataLen = bytes.length;
        if(dataLen > 0xFFFF) {
            throw new DeviceException("Data is too large 'size <= 0xFFFF'");
        }
        int seq = 0;
        int idx = 0;
        byte[] buf = new byte[0];
        boolean singleEmptyWrite = (dataLen == 0);
        while(idx < dataLen || singleEmptyWrite) {
            if(idx == 0) {
                //INIT frame
                buf = Arrays.copyOfRange(bytes, idx, idx + Math.min(dataLen, USB_REPORT_SIZE - 7));
                ByteBuffer buffer = ByteBuffer.allocate(USB_REPORT_SIZE);
                buffer.putInt((int)cid);
                buffer.put((byte)endpoint);
                buffer.putShort((short)dataLen);
                buffer.put(buf);
                for(int i = 0; i < USB_REPORT_SIZE - 7 - buf.length; i++) {
                    buffer.put((byte)0xEE);
                }
                device.write(buffer.array());
            } else {
                //CONT frame
                buf = Arrays.copyOfRange(bytes, idx, idx + Math.min(dataLen, USB_REPORT_SIZE - 5));
                ByteBuffer buffer = ByteBuffer.allocate(USB_REPORT_SIZE);
                buffer.putInt((int)cid);
                buffer.put((byte)seq);
                buffer.put(buf);
                for(int i = 0; i < USB_REPORT_SIZE - 5 - buf.length; i++) {
                    buffer.put((byte)0xEE);
                }
                device.write(buffer.array());
                seq++;
            }
            idx += buf.length;
            singleEmptyWrite = false;
        }
    }

    public byte[] read(int endpoint, long cid) throws DeviceException {
        if(endpoint < 0 || endpoint > 0xFF) {
            throw new DeviceException("Channel command (endpoint) is out of range '0 < endpoint <= 0xFF'");
        }
        if(cid < 0 || cid > 0xFFFFFFFFL) {
            throw new DeviceException("Channel id is out of range '0 < cid <= 0xFFFFFFFF'");
        }
        int timeoutMs = 5000000;
        byte[] buf = device.read(USB_REPORT_SIZE, timeoutMs);
        if(buf.length >= 3) {
            long replyCid = ((long) buf[0] & 0xFF) << 24 | ((long) buf[1] & 0xFF) << 16 | ((long) buf[2] & 0xFF) << 8 | ((long) buf[3] & 0xFF);
            int replyCmd = buf[4] & 0xFF;
            int dataLen = ((int) buf[5] & 0xFF) << 8 | ((int) buf[6] & 0xFF);
            byte[] data = Arrays.copyOfRange(buf, 7, buf.length);
            int idx = buf.length - 7;
            if(replyCmd == ERROR) {
                throwException(data[0]);
            }
            while(idx < dataLen) {
                //CONT response
                buf = device.read(USB_REPORT_SIZE, timeoutMs);
                if(buf.length < 3) {
                    throw new DeviceException("Did not receive a continuation frame after 5000 seconds.");
                }
                data = Utils.concat(data, Arrays.copyOfRange(buf, 5, buf.length));
                idx += buf.length - 5;
            }
            if(replyCid != cid) {
                throw new DeviceException("USB channel ID mismatch " + replyCid + " != " + cid);
            }
            if(replyCmd != endpoint) {
                throw new DeviceException("USB channel command mismatch " + replyCmd + " != " + endpoint);
            }
            return Arrays.copyOfRange(data, 0, dataLen);
        }
        throw new DeviceException("Did not read anything after 5000 seconds.");
    }

    public void close() {
        device.close();
    }
}
