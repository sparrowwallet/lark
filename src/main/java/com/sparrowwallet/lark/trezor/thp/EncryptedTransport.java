package com.sparrowwallet.lark.trezor.thp;

import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.bitbox02.noise.NoiseTransport;
import com.sparrowwallet.lark.trezor.DeviceTimeoutException;
import com.sparrowwallet.lark.trezor.Transport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.AEADBadTagException;
import java.util.ArrayList;
import java.util.List;

/**
 * THP encrypted transport layer.
 *
 * Wraps NoiseTransport to provide encrypted communication over an allocated THP channel.
 * Handles encryption/decryption and THP packet framing with Alternating Bit Protocol (ABP).
 *
 * Protocol flow:
 * 1. Application data is encrypted using Noise
 * 2. Encrypted payload is framed with control byte, channel ID, and CRC
 * 3. Framed message is segmented into 64-byte USB packets
 * 4. Received packets are reassembled, verified, and decrypted
 */
public class EncryptedTransport {
    private static final Logger log = LoggerFactory.getLogger(EncryptedTransport.class);

    private static final int MAX_PACKETS = 1000; // Safety limit for reassembly

    private final Transport transport;
    private final NoiseTransport noiseTransport;
    private final int channelId;

    // Alternating Bit Protocol state
    private boolean sequenceBit;
    private boolean lastReceivedAckBit;

    /**
     * Create encrypted transport.
     *
     * @param transport The underlying transport for packet I/O
     * @param noiseTransport The Noise transport for encryption/decryption
     * @param channelId The allocated channel ID
     */
    public EncryptedTransport(Transport transport, NoiseTransport noiseTransport, int channelId) {
        if(!Channel.isAllocatable(channelId)) {
            throw new IllegalArgumentException("Invalid channel ID: 0x" + String.format("%04X", channelId));
        }

        this.transport = transport;
        this.noiseTransport = noiseTransport;
        this.channelId = channelId;

        // Initialize ABP state
        this.sequenceBit = false;
        this.lastReceivedAckBit = false;
    }

    /**
     * Send encrypted message on the allocated channel.
     *
     * @param applicationData The plaintext application data to send
     * @throws DeviceException if encryption or transmission fails
     */
    public void sendMessage(byte[] applicationData) throws DeviceException {
        // Encrypt application data using Noise
        byte[] encryptedPayload = noiseTransport.writeMessage(applicationData);

        // Create control byte with sequence bit
        byte controlByte = ControlByte.createEncryptedTransport(sequenceBit, lastReceivedAckBit);

        // Segment into packets
        List<byte[]> packets = PacketCodec.segment(controlByte, channelId, encryptedPayload);

        // Send all packets
        for(byte[] packet : packets) {
            transport.write(packet);
        }

        // ABP: Wait for ACK from device
        byte[] ackPacket = transport.read();
        if(ackPacket == null || ackPacket.length != 64) {
            throw new DeviceException("Invalid ACK packet received");
        }

        // Verify it's an ACK with correct sequence bit
        ControlByte.PacketType ackType = ControlByte.getPacketType(ackPacket[0]);
        if(ackType != ControlByte.PacketType.ACK) {
            throw new DeviceException("Expected ACK, got " + ackType);
        }

        boolean ackBit = ControlByte.getAckBit(ackPacket[0]);
        if(ackBit != sequenceBit) {
            throw new DeviceException("ACK bit mismatch: expected " + sequenceBit + ", got " + ackBit);
        }

        // Toggle sequence bit for next message (ABP)
        sequenceBit = !sequenceBit;
    }

    /**
     * Receive and decrypt message from the allocated channel.
     *
     * @return Decrypted application data
     * @throws DeviceException if reception or decryption fails
     */
    public byte[] receiveMessage() throws DeviceException {
        // Read first packet to determine message type and length
        // Poll indefinitely on timeout (e.g., waiting for user button press)
        byte[] firstPacket;
        while(true) {
            try {
                firstPacket = transport.read();
                break; // Successfully read packet
            } catch(DeviceTimeoutException e) {
                // Timeout waiting for response - continue polling
                // This is expected when waiting for user interaction (button press, etc.)
                if(log.isTraceEnabled()) {
                    log.trace("Read timeout, continuing to poll for response");
                }
                continue;
            }
        }

        if(firstPacket == null || firstPacket.length != 64) {
            throw new DeviceException("Invalid first packet received");
        }

        // Verify channel ID
        int receivedChannelId = PacketCodec.getChannelId(firstPacket);
        if(receivedChannelId != channelId) {
            throw new DeviceException("Channel ID mismatch: expected 0x" +
                    String.format("%04X", channelId) + ", got 0x" +
                    String.format("%04X", receivedChannelId));
        }

        // Parse control byte
        byte controlByte = firstPacket[0];
        ControlByte.PacketType packetType = ControlByte.getPacketType(controlByte);

        // Handle different packet types
        if(packetType != ControlByte.PacketType.ENCRYPTED_TRANSPORT) {
            throw new DeviceException("Unexpected packet type: " + packetType);
        }

        // Update ABP state from received ACK bit
        boolean receivedAckBit = ControlByte.getAckBit(controlByte);
        lastReceivedAckBit = receivedAckBit;

        // Reassemble packets
        List<byte[]> packets = new ArrayList<>();
        packets.add(firstPacket);

        // Get transport payload length from first packet (includes CRC)
        int transportPayloadLength = PacketCodec.getLength(firstPacket);

        // Calculate required number of packets
        int requiredPackets = calculateRequiredPackets(transportPayloadLength);

        // Read remaining packets
        for(int i = 1; i < requiredPackets; i++) {
            if(i >= MAX_PACKETS) {
                throw new DeviceException("Too many packets received (possible protocol error)");
            }

            byte[] packet;
            while(true) {
                try {
                    packet = transport.read();
                    break;
                } catch(DeviceTimeoutException e) {
                    // Continue polling for continuation packets
                    if(log.isTraceEnabled()) {
                        log.trace("Timeout reading continuation packet {}/{}, continuing to poll", i, requiredPackets);
                    }
                    continue;
                }
            }

            if(packet == null || packet.length != 64) {
                throw new DeviceException("Invalid continuation packet received");
            }

            // Verify it's a continuation packet
            if(!ControlByte.isContinuation(packet[0])) {
                throw new DeviceException(String.format(
                    "Expected continuation packet %d/%d, got control byte 0x%02X",
                    i, requiredPackets, packet[0] & 0xFF));
            }

            // Verify channel ID matches
            int contChannelId = PacketCodec.getChannelId(packet);
            if(contChannelId != channelId) {
                throw new DeviceException("Channel ID mismatch in continuation packet");
            }

            packets.add(packet);
        }

        // Reassemble and verify CRC
        PacketCodec.ReassembledMessage message = PacketCodec.reassemble(packets);

        // Decrypt using Noise
        byte[] decryptedData;
        try {
            decryptedData = noiseTransport.readMessage(message.applicationData);
        } catch(AEADBadTagException e) {
            throw new DeviceException("Decryption failed: invalid authentication tag", e);
        }

        // ABP: Send ACK back to device
        boolean receivedSeqBit = ControlByte.getSequenceBit(controlByte);
        byte ackControlByte = ControlByte.createAck(receivedSeqBit);

        // ACK has empty payload but needs proper THP packet format
        byte[] emptyPayload = new byte[0];
        for(byte[] ackPkt : PacketCodec.segment(ackControlByte, channelId, emptyPayload)) {
            transport.write(ackPkt);
        }

        return decryptedData;
    }

    /**
     * Calculate number of packets required for a message.
     *
     * @param transportPayloadLength Length of transport payload (includes 4-byte CRC)
     * @return Number of packets needed
     */
    private int calculateRequiredPackets(int transportPayloadLength) {
        // Transport payload length already includes CRC from PacketCodec.getLength()

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

    /**
     * Get the channel ID.
     */
    public int getChannelId() {
        return channelId;
    }

    /**
     * Get the current sequence bit.
     */
    public boolean getSequenceBit() {
        return sequenceBit;
    }

    /**
     * Get the last received ACK bit.
     */
    public boolean getLastReceivedAckBit() {
        return lastReceivedAckBit;
    }
}
