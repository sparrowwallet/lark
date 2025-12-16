package com.sparrowwallet.lark.trezor.thp;

import com.sparrowwallet.lark.DeviceException;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * THP packet segmentation and reassembly.
 *
 * Handles splitting application data into THP packets (with CRC-32) and
 * reassembling received packets back into application data.
 */
public class PacketCodec {

    private static final int USB_PACKET_SIZE = 64;

    // Initiation packet: ctrl(1) + cid(2) + length(2) + payload
    private static final int INITIATION_HEADER_SIZE = 5;
    private static final int INITIATION_PAYLOAD_SIZE = USB_PACKET_SIZE - INITIATION_HEADER_SIZE;

    // Continuation packet: ctrl(1) + cid(2) + payload
    private static final int CONTINUATION_HEADER_SIZE = 3;
    private static final int CONTINUATION_PAYLOAD_SIZE = USB_PACKET_SIZE - CONTINUATION_HEADER_SIZE;

    private static final int CRC_SIZE = 4;

    /**
     * Segment application data into THP packets.
     *
     * @param controlByte Control byte for initiation packet (sequence/ack bits should be set)
     * @param channelId Channel ID
     * @param applicationData The data to send (without CRC)
     * @return List of 64-byte packets ready for transmission
     */
    public static List<byte[]> segment(byte controlByte, int channelId, byte[] applicationData) {
        // Compute transport payload = application data + CRC
        int appDataLen = (applicationData != null) ? applicationData.length : 0;
        int transportPayloadLen = appDataLen + CRC_SIZE;

        // CRC is computed with the length field value (which includes CRC)
        byte[] crc = Crc32.compute(controlByte, channelId, transportPayloadLen, applicationData);
        byte[] transportPayload = new byte[transportPayloadLen];
        if(applicationData != null && appDataLen > 0) {
            System.arraycopy(applicationData, 0, transportPayload, 0, appDataLen);
        }
        System.arraycopy(crc, 0, transportPayload, appDataLen, CRC_SIZE);

        List<byte[]> packets = new ArrayList<>();
        int offset = 0;

        // Create initiation packet
        byte[] initiationPacket = new byte[USB_PACKET_SIZE];
        initiationPacket[0] = controlByte;
        initiationPacket[1] = (byte)((channelId >> 8) & 0xFF);
        initiationPacket[2] = (byte)(channelId & 0xFF);
        // Length field includes CRC (transport payload length, not just app data)
        initiationPacket[3] = (byte)((transportPayloadLen >> 8) & 0xFF);
        initiationPacket[4] = (byte)(transportPayloadLen & 0xFF);

        int firstChunkSize = Math.min(transportPayloadLen, INITIATION_PAYLOAD_SIZE);
        System.arraycopy(transportPayload, 0, initiationPacket, INITIATION_HEADER_SIZE, firstChunkSize);
        packets.add(initiationPacket);
        offset += firstChunkSize;

        // Create continuation packets if needed
        while(offset < transportPayloadLen) {
            byte[] continuationPacket = new byte[USB_PACKET_SIZE];
            continuationPacket[0] = ControlByte.createContinuation();
            continuationPacket[1] = (byte)((channelId >> 8) & 0xFF);
            continuationPacket[2] = (byte)(channelId & 0xFF);

            int chunkSize = Math.min(transportPayloadLen - offset, CONTINUATION_PAYLOAD_SIZE);
            System.arraycopy(transportPayload, offset, continuationPacket, CONTINUATION_HEADER_SIZE, chunkSize);
            packets.add(continuationPacket);
            offset += chunkSize;
        }

        return packets;
    }

    /**
     * Result of packet reassembly.
     */
    public static class ReassembledMessage {
        public final byte controlByte;
        public final int channelId;
        public final byte[] applicationData;

        public ReassembledMessage(byte controlByte, int channelId, byte[] applicationData) {
            this.controlByte = controlByte;
            this.channelId = channelId;
            this.applicationData = applicationData;
        }
    }

    /**
     * Reassemble THP packets into application data.
     *
     * @param packets List of packets (first must be initiation, rest continuation)
     * @return Reassembled message with CRC verified
     * @throws DeviceException if packet format is invalid or CRC fails
     */
    public static ReassembledMessage reassemble(List<byte[]> packets) throws DeviceException {
        if(packets == null || packets.isEmpty()) {
            throw new DeviceException("No packets to reassemble");
        }

        // Parse initiation packet
        byte[] firstPacket = packets.get(0);
        if(firstPacket.length != USB_PACKET_SIZE) {
            throw new DeviceException("Invalid packet size: " + firstPacket.length);
        }

        byte controlByte = firstPacket[0];
        if(ControlByte.isContinuation(controlByte)) {
            throw new DeviceException("First packet must be initiation packet");
        }

        int channelId = ((firstPacket[1] & 0xFF) << 8) | (firstPacket[2] & 0xFF);
        int length = ((firstPacket[3] & 0xFF) << 8) | (firstPacket[4] & 0xFF);

        // Length field already includes CRC (transport payload size)
        int transportPayloadSize = length;

        // Reassemble transport payload from all packets
        ByteBuffer buffer = ByteBuffer.allocate(transportPayloadSize);

        // Copy from initiation packet
        int firstChunkSize = Math.min(transportPayloadSize, INITIATION_PAYLOAD_SIZE);
        buffer.put(firstPacket, INITIATION_HEADER_SIZE, firstChunkSize);

        // Copy from continuation packets
        int packetIndex = 1;
        while(buffer.position() < transportPayloadSize) {
            if(packetIndex >= packets.size()) {
                throw new DeviceException("Incomplete message: expected " + transportPayloadSize + " bytes, got " + buffer.position());
            }

            byte[] contPacket = packets.get(packetIndex++);
            if(contPacket.length != USB_PACKET_SIZE) {
                throw new DeviceException("Invalid continuation packet size: " + contPacket.length);
            }

            if(!ControlByte.isContinuation(contPacket[0])) {
                throw new DeviceException("Expected continuation packet");
            }

            int contChannelId = ((contPacket[1] & 0xFF) << 8) | (contPacket[2] & 0xFF);
            if(contChannelId != channelId) {
                throw new DeviceException("Channel ID mismatch in continuation packet");
            }

            int remaining = transportPayloadSize - buffer.position();
            int chunkSize = Math.min(remaining, CONTINUATION_PAYLOAD_SIZE);
            buffer.put(contPacket, CONTINUATION_HEADER_SIZE, chunkSize);
        }

        byte[] transportPayload = buffer.array();

        // Verify CRC
        if(!Crc32.verify(controlByte, channelId, length, transportPayload)) {
            throw new DeviceException("CRC verification failed");
        }

        // Extract application data (without CRC)
        int appDataLen = length - CRC_SIZE;
        byte[] applicationData = new byte[appDataLen];
        System.arraycopy(transportPayload, 0, applicationData, 0, appDataLen);

        return new ReassembledMessage(controlByte, channelId, applicationData);
    }

    /**
     * Parse channel ID from a packet (works for both initiation and continuation).
     *
     * @param packet The packet
     * @return Channel ID
     */
    public static int getChannelId(byte[] packet) {
        if(packet == null || packet.length < 3) {
            return -1;
        }

        return ((packet[1] & 0xFF) << 8) | (packet[2] & 0xFF);
    }

    /**
     * Parse length from initiation packet.
     *
     * @param packet The initiation packet
     * @return Application data length (excluding CRC)
     * @throws DeviceException if not an initiation packet
     */
    public static int getLength(byte[] packet) throws DeviceException {
        if(packet == null || packet.length < INITIATION_HEADER_SIZE) {
            throw new DeviceException("Invalid packet size");
        }
        if(ControlByte.isContinuation(packet[0])) {
            throw new DeviceException("Cannot get length from continuation packet");
        }

        return ((packet[3] & 0xFF) << 8) | (packet[4] & 0xFF);
    }
}
