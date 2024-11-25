package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.lark.DeviceException;
import org.hid4java.HidDevice;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class HIDTransport extends AbstractTransport {
    private static final Logger log = LoggerFactory.getLogger(HIDTransport.class);

    private final HidDevice hidDevice;

    private static final byte[] HEADER_BYTES = new byte[]{0x01, 0x01, 0x05};

    public HIDTransport(HidDevice hidDevice) {
        this.hidDevice = hidDevice;
        open();
    }

    @Override
    public void open() {
        if(hidDevice.isClosed()) {
            hidDevice.open();
            hidDevice.setNonBlocking(true);
        }
    }

    /**
     * Send data to device
     *
     * @param data data to send
     * @return the number of bytes of data sent
     */
    @Override
    public int send(byte[] data) {
        if(data == null) {
            throw new IllegalArgumentException("data cannot be null");
        }

        if(log.isDebugEnabled()) {
            log.debug("> " + Utils.bytesToHex(data));
        }

        ByteBuffer buffer = ByteBuffer.allocate(2 + data.length);
        buffer.putShort((short)data.length);
        buffer.put(data);
        data = buffer.array();

        int offset = 0;
        int seqIdx = 0;
        int length = 0;

        while(offset < data.length) {
            int headerLength = HEADER_BYTES.length + 2;
            byte[] chunk  = Arrays.copyOfRange(data, offset, Math.min(offset + 64 - headerLength, data.length));
            ByteBuffer buf = ByteBuffer.allocate(headerLength + chunk.length);
            buf.put(HEADER_BYTES);
            buf.putShort((short)seqIdx);
            buf.put(chunk);

            hidDevice.write(buf.array(), 64, (byte)0);
            length += chunk.length + 1;
            offset += 64 - headerLength;
            seqIdx++;
        }

        return length;
    }

    @Override
    public Response recv() throws DeviceException {
        int seqIdx = 0;
        hidDevice.setNonBlocking(false);
        byte[] chunk = new byte[64];
        hidDevice.read(chunk);
        hidDevice.setNonBlocking(true);

        if(chunk[0] != 0x01 || chunk[1] != 0x01 || chunk[2] != 0x05) {
            throw new DeviceException("Unexpected header in response");
        }
        ByteBuffer buf = ByteBuffer.allocate(2);
        buf.putShort((short)seqIdx);
        if(!Arrays.equals(buf.array(), Arrays.copyOfRange(chunk, 3, 5))) {
            throw new DeviceException("Unexpected sequence index in response");
        }

        int dataLength = new BigInteger(1, Arrays.copyOfRange(chunk, 5, 7)).intValue();
        byte[] data = Arrays.copyOfRange(chunk, 7, chunk.length);

        while(data.length < dataLength) {
            byte[] nextChunk = new byte[64];
            hidDevice.read(nextChunk, 1000);
            data = Utils.concat(data, Arrays.copyOfRange(nextChunk, 5, nextChunk.length));
        }

        int sw = new BigInteger(1, Arrays.copyOfRange(data, dataLength - 2, dataLength)).intValue();
        byte[] rdata = Arrays.copyOfRange(data, 0, dataLength - 2);

        if(log.isDebugEnabled()) {
            log.debug("< " + Utils.bytesToHex(rdata) + " " + Integer.toHexString(sw));
        }

        return new Response(sw, rdata);
    }

    @Override
    public Response exchange(byte[] data) throws DeviceException {
        send(data);
        return recv();
    }

    @Override
    public void close() throws IOException {
        if(hidDevice != null) {
            hidDevice.close();
        }
    }
}
