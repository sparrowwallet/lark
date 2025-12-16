package com.sparrowwallet.lark.trezor.thp;

import java.security.SecureRandom;

/**
 * THP channel management utilities.
 *
 * Channel IDs are 16-bit values with specific ranges:
 * - 0xFFFF: Broadcast channel (for allocation requests/responses)
 * - 0xFFF0-0xFFFE, 0x0000: Reserved
 * - 0x0001-0xFFEF: Allocatable channels
 */
public class Channel {

    // ===== Channel ID Constants =====

    /** Broadcast channel for allocation requests/responses */
    public static final int BROADCAST_CHANNEL_ID = 0xFFFF;

    /** First reserved channel ID */
    public static final int RESERVED_START = 0xFFF0;

    /** Last reserved channel ID (before broadcast) */
    public static final int RESERVED_END = 0xFFFE;

    /** First allocatable channel ID */
    public static final int ALLOCATABLE_START = 0x0001;

    /** Last allocatable channel ID */
    public static final int ALLOCATABLE_END = 0xFFEF;

    private static final SecureRandom random = new SecureRandom();

    // ===== Channel Validation =====

    /**
     * Check if channel ID is the broadcast channel.
     */
    public static boolean isBroadcast(int channelId) {
        return channelId == BROADCAST_CHANNEL_ID;
    }

    /**
     * Check if channel ID is reserved.
     */
    public static boolean isReserved(int channelId) {
        return channelId == 0x0000 ||
               (channelId >= RESERVED_START && channelId <= RESERVED_END);
    }

    /**
     * Check if channel ID is allocatable.
     */
    public static boolean isAllocatable(int channelId) {
        return channelId >= ALLOCATABLE_START && channelId <= ALLOCATABLE_END;
    }

    /**
     * Check if channel ID is valid (not reserved).
     */
    public static boolean isValid(int channelId) {
        return isBroadcast(channelId) || isAllocatable(channelId);
    }

    // ===== Nonce Generation =====

    /**
     * Generate a random 8-byte nonce for channel allocation.
     * Used to match allocation requests with responses.
     *
     * @return 8-byte random nonce
     */
    public static byte[] generateNonce() {
        byte[] nonce = new byte[8];
        random.nextBytes(nonce);
        return nonce;
    }

    /**
     * Compare two nonces for equality.
     *
     * @param nonce1 First nonce
     * @param nonce2 Second nonce
     * @return true if nonces match, false otherwise
     */
    public static boolean nonceMatches(byte[] nonce1, byte[] nonce2) {
        if(nonce1 == null || nonce2 == null) {
            return false;
        }
        if(nonce1.length != 8 || nonce2.length != 8) {
            return false;
        }
        for(int i = 0; i < 8; i++) {
            if(nonce1[i] != nonce2[i]) {
                return false;
            }
        }
        return true;
    }

    // ===== Channel ID Parsing =====

    /**
     * Parse channel ID from big-endian bytes.
     *
     * @param bytes Buffer containing channel ID
     * @param offset Offset in buffer
     * @return Channel ID as int (0-65535)
     */
    public static int parseChannelId(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFF) << 8) | (bytes[offset + 1] & 0xFF);
    }

    /**
     * Write channel ID to buffer in big-endian format.
     *
     * @param channelId The channel ID
     * @param bytes Target buffer
     * @param offset Offset in buffer
     */
    public static void writeChannelId(int channelId, byte[] bytes, int offset) {
        bytes[offset] = (byte)((channelId >> 8) & 0xFF);
        bytes[offset + 1] = (byte)(channelId & 0xFF);
    }

    /**
     * Convert channel ID to 2-byte array (big-endian).
     *
     * @param channelId The channel ID
     * @return 2-byte array
     */
    public static byte[] channelIdToBytes(int channelId) {
        return new byte[] {
            (byte)((channelId >> 8) & 0xFF),
            (byte)(channelId & 0xFF)
        };
    }
}
