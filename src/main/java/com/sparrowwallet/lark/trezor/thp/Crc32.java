package com.sparrowwallet.lark.trezor.thp;

import java.nio.ByteBuffer;
import java.util.zip.CRC32;

/**
 * CRC-32-IEEE computation for THP transport layer.
 *
 * Polynomial: 0x04C11DB7 (standard form) / 0xEDB88320 (reversed)
 * This matches java.util.zip.CRC32 implementation.
 *
 * CRC is computed over:
 * - Control byte (1 byte)
 * - Channel ID (2 bytes, big-endian)
 * - Length (2 bytes, big-endian)
 * - Transport payload (variable)
 *
 * Result is 4 bytes in big-endian format, appended to the transport payload.
 */
public class Crc32 {

    /**
     * Compute CRC-32 for a THP packet.
     *
     * @param controlByte The control byte
     * @param channelId The channel ID (will be written as 2 bytes big-endian)
     * @param length The payload length (will be written as 2 bytes big-endian)
     * @param payload The transport payload
     * @return 4-byte CRC in big-endian format
     */
    public static byte[] compute(byte controlByte, int channelId, int length, byte[] payload) {
        CRC32 crc = new CRC32();

        // Control byte
        crc.update(controlByte);

        // Channel ID (2 bytes, big-endian)
        crc.update((byte)((channelId >> 8) & 0xFF));
        crc.update((byte)(channelId & 0xFF));

        // Length (2 bytes, big-endian)
        crc.update((byte)((length >> 8) & 0xFF));
        crc.update((byte)(length & 0xFF));

        // Payload
        if(payload != null && payload.length > 0) {
            crc.update(payload);
        }

        // Return 4 bytes in big-endian
        long crcValue = crc.getValue();
        return new byte[] {
            (byte)((crcValue >> 24) & 0xFF),
            (byte)((crcValue >> 16) & 0xFF),
            (byte)((crcValue >> 8) & 0xFF),
            (byte)(crcValue & 0xFF)
        };
    }

    /**
     * Compute CRC-32 for a THP packet with payload offset and length.
     *
     * @param controlByte The control byte
     * @param channelId The channel ID
     * @param length The payload length field value
     * @param payload The buffer containing transport payload
     * @param payloadOffset Offset in payload buffer
     * @param payloadLength Actual payload bytes to include in CRC
     * @return 4-byte CRC in big-endian format
     */
    public static byte[] compute(byte controlByte, int channelId, int length, byte[] payload, int payloadOffset, int payloadLength) {
        CRC32 crc = new CRC32();

        // Control byte
        crc.update(controlByte);

        // Channel ID (2 bytes, big-endian)
        crc.update((byte)((channelId >> 8) & 0xFF));
        crc.update((byte)(channelId & 0xFF));

        // Length (2 bytes, big-endian)
        crc.update((byte)((length >> 8) & 0xFF));
        crc.update((byte)(length & 0xFF));

        // Payload
        if(payload != null && payloadLength > 0) {
            crc.update(payload, payloadOffset, payloadLength);
        }

        // Return 4 bytes in big-endian
        long crcValue = crc.getValue();
        return new byte[] {
            (byte)((crcValue >> 24) & 0xFF),
            (byte)((crcValue >> 16) & 0xFF),
            (byte)((crcValue >> 8) & 0xFF),
            (byte)(crcValue & 0xFF)
        };
    }

    /**
     * Verify CRC-32 for a THP packet.
     *
     * @param controlByte The control byte
     * @param channelId The channel ID
     * @param length The payload length field value
     * @param payloadWithCrc The transport payload with 4-byte CRC appended
     * @return true if CRC is valid, false otherwise
     */
    public static boolean verify(byte controlByte, int channelId, int length, byte[] payloadWithCrc) {
        if(payloadWithCrc == null || payloadWithCrc.length < 4) {
            return false;
        }

        int payloadLength = payloadWithCrc.length - 4;

        // Compute CRC over payload (excluding the CRC itself)
        byte[] computed = compute(controlByte, channelId, length, payloadWithCrc, 0, payloadLength);

        // Compare with appended CRC (last 4 bytes)
        return computed[0] == payloadWithCrc[payloadLength] &&
               computed[1] == payloadWithCrc[payloadLength + 1] &&
               computed[2] == payloadWithCrc[payloadLength + 2] &&
               computed[3] == payloadWithCrc[payloadLength + 3];
    }

    /**
     * Append CRC-32 to payload data.
     *
     * @param controlByte The control byte
     * @param channelId The channel ID
     * @param length The payload length field value
     * @param payload The transport payload
     * @return New array with payload + 4-byte CRC appended
     */
    public static byte[] appendCrc(byte controlByte, int channelId, int length, byte[] payload) {
        byte[] crc = compute(controlByte, channelId, length, payload);

        int payloadLen = (payload != null) ? payload.length : 0;
        byte[] result = new byte[payloadLen + 4];

        if(payload != null && payloadLen > 0) {
            System.arraycopy(payload, 0, result, 0, payloadLen);
        }

        System.arraycopy(crc, 0, result, payloadLen, 4);

        return result;
    }
}
