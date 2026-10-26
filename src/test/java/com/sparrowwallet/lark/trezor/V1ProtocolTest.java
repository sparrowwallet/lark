package com.sparrowwallet.lark.trezor;

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.trezor.generated.TrezorMessage;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageManagement;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(value = 10, unit = TimeUnit.SECONDS)
public class V1ProtocolTest {
    private static final int PACKET_SIZE = 64;

    @Test
    public void testUnknownMessageTypeIsReportedByNumber() {
        V1Protocol protocol = new V1Protocol(new ReplyTransport(chunk(0x7FFF, new byte[0])), null, null);

        DeviceException e = assertThrows(DeviceException.class, () -> protocol.callRaw(TrezorMessageManagement.GetFeatures.newBuilder().build()));
        assertInstanceOf(InvalidProtocolBufferException.class, e.getCause());
        assertTrue(e.getCause().getMessage().contains("32767"));
    }

    @Test
    public void testKnownMessageTypeIsParsed() throws DeviceException {
        byte[] features = TrezorMessageManagement.Features.newBuilder().setMajorVersion(2).setMinorVersion(12).setPatchVersion(5).build().toByteArray();
        V1Protocol protocol = new V1Protocol(new ReplyTransport(chunk(TrezorMessage.MessageType.MessageType_Features.getNumber(), features)), null, null);

        Message response = protocol.callRaw(TrezorMessageManagement.GetFeatures.newBuilder().build());
        TrezorMessageManagement.Features parsed = assertInstanceOf(TrezorMessageManagement.Features.class, response);
        assertEquals(12, parsed.getMinorVersion());
    }

    private static byte[] chunk(int messageType, byte[] payload) {
        ByteBuffer chunk = ByteBuffer.allocate(PACKET_SIZE).order(ByteOrder.BIG_ENDIAN);
        chunk.put(new byte[] { '?', '#', '#' });
        chunk.putShort((short)messageType);
        chunk.putInt(payload.length);
        chunk.put(payload);

        return chunk.array();
    }

    private static class ReplyTransport implements Transport {
        private final Deque<byte[]> deviceChunks = new ArrayDeque<>();
        private boolean closed;

        private ReplyTransport(byte[]... reply) {
            for(byte[] chunk : reply) {
                deviceChunks.add(chunk);
            }
        }

        @Override
        public void write(byte[] packet) {
        }

        @Override
        public byte[] read() throws DeviceException {
            return read(0);
        }

        @Override
        public byte[] read(int timeoutMs) throws DeviceException {
            byte[] chunk = deviceChunks.poll();
            if(chunk == null) {
                throw new DeviceException("No chunk queued");
            }

            return chunk;
        }

        @Override
        public void close() {
            closed = true;
        }

        @Override
        public boolean isClosed() {
            return closed;
        }
    }
}
