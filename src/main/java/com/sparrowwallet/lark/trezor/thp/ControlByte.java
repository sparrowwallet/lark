package com.sparrowwallet.lark.trezor.thp;

/**
 * THP control byte utilities.
 *
 * The control byte determines packet type and contains sequence/acknowledgment bits
 * for the Alternating Bit Protocol (ABP).
 *
 * Packet Types:
 * - Initiation packets (bit 7 = 0): Start of a new message
 * - Continuation packets (bit 7 = 1): Continuation of a segmented message
 * - Control packets: Channel allocation, errors, ping/pong
 * - Data packets: Handshake and encrypted transport messages with SEQ/ACK bits
 */
public class ControlByte {

    // ===== Masks and Base Values =====

    private static final int CONTINUATION_MASK = 0x80;
    private static final int CONTINUATION_FLAG = 0x80;

    // Control packet types (exact match required)
    public static final byte CHANNEL_ALLOCATION_REQ = 0x40;
    public static final byte CHANNEL_ALLOCATION_RESP = 0x41;
    public static final byte TRANSPORT_ERROR = 0x42;
    public static final byte PING = 0x43;
    public static final byte PONG = 0x44;

    // Data packet masks and base values
    private static final int ACK_MASK = 0xF7;
    private static final int ACK_BASE = 0x20;

    private static final int DATA_PACKET_MASK = 0xE7;
    private static final int HANDSHAKE_INIT_REQ = 0x00;
    private static final int HANDSHAKE_INIT_RESP = 0x01;
    private static final int HANDSHAKE_COMP_REQ = 0x02;
    private static final int HANDSHAKE_COMP_RESP = 0x03;
    private static final int ENCRYPTED_TRANSPORT = 0x04;

    // Data packet bit positions
    private static final int SEQ_BIT = 0x10;  // Bit 4
    private static final int ACK_BIT = 0x08;  // Bit 3

    // ===== Packet Type Enumeration =====

    public enum PacketType {
        INITIATION,
        CONTINUATION,
        CHANNEL_ALLOCATION_REQ,
        CHANNEL_ALLOCATION_RESP,
        TRANSPORT_ERROR,
        PING,
        PONG,
        ACK,
        HANDSHAKE_INIT_REQ,
        HANDSHAKE_INIT_RESP,
        HANDSHAKE_COMP_REQ,
        HANDSHAKE_COMP_RESP,
        ENCRYPTED_TRANSPORT
    }

    // ===== Type Detection =====

    /**
     * Check if control byte indicates a continuation packet.
     */
    public static boolean isContinuation(byte ctrlByte) {
        return (ctrlByte & CONTINUATION_MASK) == CONTINUATION_FLAG;
    }

    /**
     * Check if control byte indicates an initiation packet.
     */
    public static boolean isInitiation(byte ctrlByte) {
        return (ctrlByte & CONTINUATION_MASK) == 0;
    }

    /**
     * Get the packet type from control byte.
     */
    public static PacketType getPacketType(byte ctrlByte) {
        int ctrl = ctrlByte & 0xFF;

        // Check continuation first
        if(isContinuation(ctrlByte)) {
            return PacketType.CONTINUATION;
        }

        // Check control packets (exact match)
        if(ctrl == CHANNEL_ALLOCATION_REQ) return PacketType.CHANNEL_ALLOCATION_REQ;
        if(ctrl == CHANNEL_ALLOCATION_RESP) return PacketType.CHANNEL_ALLOCATION_RESP;
        if(ctrl == TRANSPORT_ERROR) return PacketType.TRANSPORT_ERROR;
        if(ctrl == PING) return PacketType.PING;
        if(ctrl == PONG) return PacketType.PONG;

        // Check ACK packet
        if((ctrl & ACK_MASK) == ACK_BASE) {
            return PacketType.ACK;
        }

        // Check data packets (masked match)
        int masked = ctrl & DATA_PACKET_MASK;
        switch(masked) {
            case HANDSHAKE_INIT_REQ: return PacketType.HANDSHAKE_INIT_REQ;
            case HANDSHAKE_INIT_RESP: return PacketType.HANDSHAKE_INIT_RESP;
            case HANDSHAKE_COMP_REQ: return PacketType.HANDSHAKE_COMP_REQ;
            case HANDSHAKE_COMP_RESP: return PacketType.HANDSHAKE_COMP_RESP;
            case ENCRYPTED_TRANSPORT: return PacketType.ENCRYPTED_TRANSPORT;
            default: return PacketType.INITIATION; // Unknown, treat as generic initiation
        }
    }

    // ===== Data Packet SEQ/ACK Bits =====

    /**
     * Extract sequence bit from data packet control byte.
     * @return true if sequence bit is set (seq=1), false otherwise (seq=0)
     */
    public static boolean getSequenceBit(byte ctrlByte) {
        return (ctrlByte & SEQ_BIT) != 0;
    }

    /**
     * Extract ACK bit from data packet control byte.
     * @return true if ACK bit is set, false otherwise
     */
    public static boolean getAckBit(byte ctrlByte) {
        return (ctrlByte & ACK_BIT) != 0;
    }

    /**
     * Set sequence bit in data packet control byte.
     * @param ctrlByte The base control byte
     * @param sequenceBit The sequence bit value (true = 1, false = 0)
     * @return Control byte with sequence bit set
     */
    public static byte setSequenceBit(byte ctrlByte, boolean sequenceBit) {
        if(sequenceBit) {
            return (byte)(ctrlByte | SEQ_BIT);
        } else {
            return (byte)(ctrlByte & ~SEQ_BIT);
        }
    }

    /**
     * Set ACK bit in data packet control byte.
     * @param ctrlByte The base control byte
     * @param ackBit The ACK bit value (true = set, false = clear)
     * @return Control byte with ACK bit set
     */
    public static byte setAckBit(byte ctrlByte, boolean ackBit) {
        if(ackBit) {
            return (byte)(ctrlByte | ACK_BIT);
        } else {
            return (byte)(ctrlByte & ~ACK_BIT);
        }
    }

    // ===== Control Byte Construction =====

    /**
     * Create control byte for continuation packet.
     */
    public static byte createContinuation() {
        return (byte)CONTINUATION_FLAG;
    }

    /**
     * Create control byte for channel allocation request.
     * @param sequenceBit ABP sequence bit (typically false for allocation)
     * @param ackBit ABP acknowledgment bit (typically false for allocation)
     */
    public static byte createChannelAllocationReq(boolean sequenceBit, boolean ackBit) {
        return CHANNEL_ALLOCATION_REQ;
    }

    /**
     * Create control byte for channel allocation response.
     * @param sequenceBit ABP sequence bit (typically false for allocation)
     * @param ackBit ABP acknowledgment bit (typically false for allocation)
     */
    public static byte createChannelAllocationResp(boolean sequenceBit, boolean ackBit) {
        return CHANNEL_ALLOCATION_RESP;
    }

    /**
     * Create control byte for handshake initiation request.
     * @param sequenceBit ABP sequence bit
     * @param ackBit ABP acknowledgment bit
     */
    public static byte createHandshakeInitReq(boolean sequenceBit, boolean ackBit) {
        byte ctrl = (byte)HANDSHAKE_INIT_REQ;
        ctrl = setSequenceBit(ctrl, sequenceBit);
        ctrl = setAckBit(ctrl, ackBit);
        return ctrl;
    }

    /**
     * Create control byte for handshake initiation response.
     * @param sequenceBit ABP sequence bit
     * @param ackBit ABP acknowledgment bit
     */
    public static byte createHandshakeInitResp(boolean sequenceBit, boolean ackBit) {
        byte ctrl = (byte)HANDSHAKE_INIT_RESP;
        ctrl = setSequenceBit(ctrl, sequenceBit);
        ctrl = setAckBit(ctrl, ackBit);
        return ctrl;
    }

    /**
     * Create control byte for handshake completion request.
     * @param sequenceBit ABP sequence bit
     * @param ackBit ABP acknowledgment bit
     */
    public static byte createHandshakeCompReq(boolean sequenceBit, boolean ackBit) {
        byte ctrl = (byte)HANDSHAKE_COMP_REQ;
        ctrl = setSequenceBit(ctrl, sequenceBit);
        ctrl = setAckBit(ctrl, ackBit);
        return ctrl;
    }

    /**
     * Create control byte for handshake completion response.
     * @param sequenceBit ABP sequence bit
     * @param ackBit ABP acknowledgment bit
     */
    public static byte createHandshakeCompResp(boolean sequenceBit, boolean ackBit) {
        byte ctrl = (byte)HANDSHAKE_COMP_RESP;
        ctrl = setSequenceBit(ctrl, sequenceBit);
        ctrl = setAckBit(ctrl, ackBit);
        return ctrl;
    }

    /**
     * Create control byte for encrypted transport message.
     * @param sequenceBit ABP sequence bit
     * @param ackBit ABP acknowledgment bit
     */
    public static byte createEncryptedTransport(boolean sequenceBit, boolean ackBit) {
        byte ctrl = (byte)ENCRYPTED_TRANSPORT;
        ctrl = setSequenceBit(ctrl, sequenceBit);
        ctrl = setAckBit(ctrl, ackBit);
        return ctrl;
    }

    /**
     * Create control byte for ACK-only packet.
     * @param ackBit The sequence number being acknowledged
     */
    public static byte createAck(boolean ackBit) {
        byte ctrl = (byte)ACK_BASE;
        return setAckBit(ctrl, ackBit);
    }

    // ===== String Representation =====

    /**
     * Get human-readable description of control byte.
     */
    public static String toString(byte ctrlByte) {
        PacketType type = getPacketType(ctrlByte);
        StringBuilder sb = new StringBuilder();
        sb.append(type);

        // Add SEQ/ACK info for data packets
        if(type == PacketType.HANDSHAKE_INIT_REQ || type == PacketType.HANDSHAKE_INIT_RESP ||
           type == PacketType.HANDSHAKE_COMP_REQ || type == PacketType.HANDSHAKE_COMP_RESP ||
           type == PacketType.ENCRYPTED_TRANSPORT || type == PacketType.ACK) {
            sb.append(" (seq=").append(getSequenceBit(ctrlByte) ? "1" : "0");
            sb.append(", ack=").append(getAckBit(ctrlByte) ? "1" : "0").append(")");
        }

        return sb.toString();
    }
}
