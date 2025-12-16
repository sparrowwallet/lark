package com.sparrowwallet.lark.trezor.thp;

import com.google.protobuf.InvalidProtocolBufferException;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageThp;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * THP channel allocation message builders and parsers.
 *
 * Channel allocation occurs on the broadcast channel (0xFFFF) before the handshake.
 * The host sends a request with a nonce and protocol version, and the device responds
 * with the matching nonce, an allocated channel ID, and device properties.
 */
public class ChannelAllocationMessages {

    /** THP protocol version v1 */
    public static final int PROTOCOL_VERSION_V1 = 0x0001;

    /**
     * Channel allocation response containing channel ID and device properties.
     */
    public static class AllocationResponse {
        public final int channelId;
        public final TrezorMessageThp.ThpDeviceProperties deviceProperties;
        public final byte[] devicePropertiesBytes;

        public AllocationResponse(int channelId, TrezorMessageThp.ThpDeviceProperties deviceProperties, byte[] devicePropertiesBytes) {
            this.channelId = channelId;
            this.deviceProperties = deviceProperties;
            this.devicePropertiesBytes = devicePropertiesBytes;
        }
    }

    /**
     * Build channel allocation request message.
     *
     * Format: nonce (8 bytes only)
     *
     * @param nonce 8-byte nonce for matching request/response
     * @param protocolVersion Unused (kept for backward compatibility)
     * @return Channel allocation request (8 bytes)
     */
    public static byte[] buildAllocationRequest(byte[] nonce, int protocolVersion) {
        if(nonce == null || nonce.length != 8) {
            throw new IllegalArgumentException("Nonce must be 8 bytes");
        }

        // Per THP spec, ChannelAllocationRequest is ONLY the 8-byte nonce
        // No protocol version field
        return nonce;
    }

    /**
     * Parse channel allocation response message.
     *
     * Format: nonce (8 bytes) + channel_id (2 bytes BE) + device_properties (protobuf)
     *
     * @param message The received allocation response
     * @param expectedNonce The nonce from the request
     * @return Allocation response with channel ID and device properties
     * @throws DeviceException if message format is invalid or nonce doesn't match
     */
    public static AllocationResponse parseAllocationResponse(byte[] message, byte[] expectedNonce) throws DeviceException {
        if(message == null || message.length < 10) {
            throw new DeviceException("Allocation response must be at least 10 bytes, got " + (message == null ? "null" : message.length));
        }

        // Extract and verify nonce
        byte[] responseNonce = new byte[8];
        System.arraycopy(message, 0, responseNonce, 0, 8);

        if(!Channel.nonceMatches(expectedNonce, responseNonce)) {
            throw new DeviceException("Allocation response nonce mismatch. Expected: " + com.sparrowwallet.drongo.Utils.bytesToHex(expectedNonce) +
                    ", got: " + com.sparrowwallet.drongo.Utils.bytesToHex(responseNonce));
        }

        // Extract channel ID
        int channelId = ((message[8] & 0xFF) << 8) | (message[9] & 0xFF);

        if(!Channel.isAllocatable(channelId)) {
            throw new DeviceException("Invalid allocated channel ID: 0x" + String.format("%04X", channelId));
        }

        // Extract and parse device properties
        byte[] devicePropertiesBytes = new byte[message.length - 10];
        System.arraycopy(message, 10, devicePropertiesBytes, 0, devicePropertiesBytes.length);

        TrezorMessageThp.ThpDeviceProperties deviceProperties;
        try {
            deviceProperties = TrezorMessageThp.ThpDeviceProperties.parseFrom(devicePropertiesBytes);
        } catch(InvalidProtocolBufferException e) {
            throw new DeviceException("Failed to parse device properties", e);
        }

        return new AllocationResponse(channelId, deviceProperties, devicePropertiesBytes);
    }
}
