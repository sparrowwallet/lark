package com.sparrowwallet.lark.trezor.thp;

import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.trezor.Transport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * THP channel allocation protocol.
 *
 * Handles requesting channel allocation from the device on the broadcast channel (0xFFFF).
 * The allocation must complete before the handshake can begin.
 *
 * Protocol flow:
 * 1. Generate nonce and build allocation request
 * 2. Send request on broadcast channel with CHANNEL_ALLOCATION_REQ control byte
 * 3. Receive allocation response with channel ID and device properties
 * 4. Device properties are used as Noise protocol prologue
 */
public class ChannelAllocator {
    private static final Logger log = LoggerFactory.getLogger(ChannelAllocator.class);

    private static final int MAX_PACKETS = 100; // Safety limit for reassembly

    private final Transport transport;

    /**
     * Create channel allocator.
     *
     * @param transport The transport for sending/receiving packets
     */
    public ChannelAllocator(Transport transport) {
        this.transport = transport;
    }

    /**
     * Request channel allocation from the device.
     *
     * @param protocolVersion The THP protocol version to request
     * @return Allocation response with channel ID and device properties
     * @throws DeviceException if allocation fails
     */
    public ChannelAllocationMessages.AllocationResponse allocateChannel(int protocolVersion) throws DeviceException {
        // Generate nonce for request/response matching
        byte[] nonce = Channel.generateNonce();

        // Build allocation request
        byte[] requestPayload = ChannelAllocationMessages.buildAllocationRequest(nonce, protocolVersion);

        if(log.isDebugEnabled()) {
            log.debug("Sending channel allocation request (nonce: {}, {} bytes)", com.sparrowwallet.drongo.Utils.bytesToHex(nonce), requestPayload.length);
        }

        // Send allocation request on broadcast channel
        sendAllocationRequest(requestPayload);

        if(log.isDebugEnabled()) {
            log.debug("Waiting for channel allocation response...");
        }

        // Receive and parse allocation response
        byte[] responsePayload = receiveAllocationResponse();

        if(log.isDebugEnabled()) {
            log.debug("Received channel allocation response ({} bytes)", responsePayload.length);
        }

        return ChannelAllocationMessages.parseAllocationResponse(responsePayload, nonce);
    }

    /**
     * Send allocation request on broadcast channel.
     */
    private void sendAllocationRequest(byte[] payload) throws DeviceException {
        // Create control byte for channel allocation request
        // Sequence and ACK bits are 0 for allocation messages
        byte controlByte = ControlByte.createChannelAllocationReq(false, false);

        // Segment into packets with broadcast channel ID
        List<byte[]> packets = PacketCodec.segment(controlByte, Channel.BROADCAST_CHANNEL_ID, payload);

        if(log.isDebugEnabled()) {
            log.debug("Sending {} packet(s) on broadcast channel 0xFFFF",  packets.size());
            for(int i = 0; i < packets.size(); i++) {
                log.debug("Packet {}: {}", i, com.sparrowwallet.drongo.Utils.bytesToHex(packets.get(i)));
            }
        }

        // Send all packets
        for(byte[] packet : packets) {
            transport.write(packet);
        }
    }

    /**
     * Receive allocation response from broadcast channel.
     */
    private byte[] receiveAllocationResponse() throws DeviceException {
        List<byte[]> packets = new ArrayList<>();

        // Read first packet to determine message length
        byte[] firstPacket = transport.read();
        if(firstPacket == null || firstPacket.length != 64) {
            throw new DeviceException("Invalid first packet received");
        }

        // Verify it's an allocation response
        byte controlByte = firstPacket[0];
        if(ControlByte.getPacketType(controlByte) != ControlByte.PacketType.CHANNEL_ALLOCATION_RESP) {
            throw new DeviceException("Expected CHANNEL_ALLOCATION_RES, got " + ControlByte.getPacketType(controlByte));
        }

        // Verify broadcast channel
        int channelId = PacketCodec.getChannelId(firstPacket);
        if(channelId != Channel.BROADCAST_CHANNEL_ID) {
            throw new DeviceException("Expected broadcast channel, got 0x" + String.format("%04X", channelId));
        }

        packets.add(firstPacket);

        // Get application data length from first packet
        int totalLength = PacketCodec.getLength(firstPacket);

        // Calculate required number of packets
        int requiredPackets = calculateRequiredPackets(totalLength);

        // Read remaining packets
        for(int i = 1; i < requiredPackets; i++) {
            if(i >= MAX_PACKETS) {
                throw new DeviceException("Too many packets received (possible protocol error)");
            }

            byte[] packet = transport.read();
            if(packet == null || packet.length != 64) {
                throw new DeviceException("Invalid continuation packet received");
            }

            // Verify it's a continuation packet
            if(!ControlByte.isContinuation(packet[0])) {
                throw new DeviceException("Expected continuation packet");
            }

            // Verify channel ID matches
            int contChannelId = PacketCodec.getChannelId(packet);
            if(contChannelId != Channel.BROADCAST_CHANNEL_ID) {
                throw new DeviceException("Channel ID mismatch in continuation packet");
            }

            packets.add(packet);
        }

        // Reassemble packets into application data
        PacketCodec.ReassembledMessage message = PacketCodec.reassemble(packets);
        return message.applicationData;
    }

    /**
     * Calculate number of packets required for a message.
     *
     * @param transportPayloadLength Length from packet header (includes CRC)
     * @return Number of packets needed
     */
    private int calculateRequiredPackets(int transportPayloadLength) {
        // Length already includes CRC (no need to add 4)

        // First packet: 5-byte header + 59 bytes payload
        int firstPacketPayload = 59;

        if(transportPayloadLength <= firstPacketPayload) {
            return 1;
        }

        // Remaining bytes need continuation packets
        int remainingBytes = transportPayloadLength - firstPacketPayload;

        // Each continuation packet: 3-byte header + 61 bytes payload
        int continuationPacketPayload = 61;

        int continuationPackets = (remainingBytes + continuationPacketPayload - 1) / continuationPacketPayload;

        return 1 + continuationPackets;
    }
}
