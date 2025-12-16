package com.sparrowwallet.lark.trezor;

import com.google.protobuf.Message;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.trezor.generated.TrezorMessage;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageCommon;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageManagement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Factory for creating Protocol instances with automatic version detection.
 *
 * Based on Python reference implementation's protocol probing approach:
 * 1. Send a v1-formatted Ping message
 * 2. If device responds with Failure(InvalidProtocol) → V2-only (T3W1)
 * 3. If device responds with anything else → V1-capable
 * 4. For V1-capable devices, check firmware version to decide V1 vs V2
 */
class ProtocolFactory {
    private static final Logger log = LoggerFactory.getLogger(ProtocolFactory.class);

    private static final int PROBE_TIMEOUT_MS = 2000;

    /**
     * Create Protocol with automatic version detection and custom credential store.
     *
     * @param transport The transport for packet I/O
     * @param ui User interaction callbacks
     * @param callbacks Protocol callbacks for device communication
     * @param credentialStore Credential storage for V2/THP pairing
     * @return Appropriate Protocol implementation (V1 or V2)
     * @throws DeviceException if protocol creation fails
     */
    static Protocol createProtocol(Transport transport, TrezorUI ui, ProtocolCallbacks callbacks, TrezorNoiseConfig credentialStore) throws DeviceException {
        // Probe for V1 protocol support
        boolean supportsV1 = probeV1Protocol(transport);

        if(supportsV1) {
            if(log.isDebugEnabled()) {
                log.debug("Device supports V1 protocol");
            }

            // Create V1 protocol instance
            return new V1Protocol(transport, ui, callbacks);
        } else {
            if(log.isDebugEnabled()) {
                log.debug("Device is V2-only (THP) - likely T3W1");
            }

            // Device is V2-only
            return new V2Protocol(transport, ui, callbacks, credentialStore);
        }
    }

    /**
     * Probe transport to determine if it supports V1 protocol.
     * Based on Python reference implementation.
     *
     * Sends a Ping message in V1 format and checks response:
     * - Failure(InvalidProtocol) → V2-only device
     * - Any other response → V1-capable device
     *
     * @param transport The transport
     * @return true if device supports V1, false if V2-only
     * @throws DeviceException if probing fails
     */
    private static boolean probeV1Protocol(Transport transport) throws DeviceException {
        try {
            // Flush any buffered packets from previous communication attempts
            // Read and discard until timeout (50ms)
            try {
                while(true) {
                    transport.read(50);
                }
            } catch(DeviceException e) {
                // Timeout is expected when buffer is empty
            }

            // Send a Ping message using V1 protocol format
            TrezorMessageManagement.Ping ping = TrezorMessageManagement.Ping.newBuilder().setMessage("protocol-v1-probe").build();

            // Encode and write using V1 format
            int msgType = getMessageType(ping);
            byte[] msgBytes = ping.toByteArray();
            writeV1Message(transport, msgType, msgBytes);

            // Read response
            MessageResponse response = readV1Message(transport);

            if(log.isDebugEnabled()) {
                log.debug("V1 probe response: type=0x{}, {} bytes: {}",
                        String.format("%04X", response.messageType),
                        response.messageBytes.length,
                        com.sparrowwallet.drongo.Utils.bytesToHex(response.messageBytes));
            }

            // Check if it's a Failure with InvalidProtocol
            int failureType = TrezorMessage.MessageType.MessageType_Failure.getNumber();
            if(response.messageType == failureType) {
                try {
                    // Trim trailing zeros (padding) before parsing protobuf
                    int actualLength = response.messageBytes.length;
                    while(actualLength > 0 && response.messageBytes[actualLength - 1] == 0) {
                        actualLength--;
                    }
                    byte[] trimmed = java.util.Arrays.copyOf(response.messageBytes, actualLength);

                    TrezorMessageCommon.Failure failure = TrezorMessageCommon.Failure.parseFrom(trimmed);

                    if(failure.getCode() == TrezorMessageCommon.Failure.FailureType.Failure_InvalidProtocol) {
                        // Device rejected V1 protocol - it's THP-only
                        return false;
                    }
                } catch(com.google.protobuf.InvalidProtocolBufferException e) {
                    // Invalid protobuf response - likely V2-only device returning garbage
                    if(log.isDebugEnabled()) {
                        log.debug("Failed to parse Failure response - assuming V2-only device", e);
                    }
                    return false;
                }
            }

            // Any other response means V1 is supported
            return true;
        } catch(Exception e) {
            if(log.isDebugEnabled()) {
                log.debug("Error during V1 protocol probe", e);
            }
            // On error, assume V1 not supported
            return false;
        }
    }

    /**
     * Write a message using V1 protocol format.
     * Format: "?##" + 2-byte type (BE) + 4-byte length (BE) + data
     */
    private static void writeV1Message(Transport transport, int msgType, byte[] msgData) throws DeviceException {
        // Create message: type (2 bytes) + length (4 bytes) + data
        ByteBuffer buffer = ByteBuffer.allocate(2 + 4 + msgData.length);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putShort((short)msgType);
        buffer.putInt(msgData.length);
        buffer.put(msgData);

        byte[] fullMessage = buffer.array();

        // Write in 64-byte chunks
        int chunkSize = 64;
        int offset = 0;
        boolean firstChunk = true;

        while(offset < fullMessage.length) {
            byte[] chunk = new byte[chunkSize];
            chunk[0] = (byte)'?';

            int headerSize = firstChunk ? 3 : 1; // "?##" vs "?"
            if(firstChunk) {
                chunk[1] = (byte)'#';
                chunk[2] = (byte)'#';
            }

            int copyLen = Math.min(chunkSize - headerSize, fullMessage.length - offset);
            System.arraycopy(fullMessage, offset, chunk, headerSize, copyLen);

            transport.write(chunk);
            offset += copyLen;
            firstChunk = false;
        }
    }

    /**
     * Read a message using V1 protocol format.
     * Format: "?##" + 2-byte type (BE) + 4-byte length (BE) + data
     */
    private static MessageResponse readV1Message(Transport transport) throws DeviceException {
        try {
            // Read first chunk
            byte[] firstChunk = transport.read(PROBE_TIMEOUT_MS);

            if(firstChunk[0] != '?' || firstChunk[1] != '#' || firstChunk[2] != '#') {
                throw new DeviceException("Invalid V1 protocol header");
            }

            // Parse header (2-byte type + 4-byte length)
            ByteBuffer headerBuf = ByteBuffer.wrap(firstChunk, 3, 6);
            headerBuf.order(ByteOrder.BIG_ENDIAN);
            int msgType = headerBuf.getShort() & 0xFFFF;
            int msgLen = headerBuf.getInt();

            // Read message data
            ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
            int firstChunkDataLen = Math.min(firstChunk.length - 9, msgLen);
            dataStream.write(firstChunk, 9, firstChunkDataLen);

            // Read continuation chunks if needed
            while(dataStream.size() < msgLen) {
                byte[] chunk = transport.read(PROBE_TIMEOUT_MS);
                if(chunk[0] != '?') {
                    throw new DeviceException("Invalid V1 continuation chunk");
                }
                int copyLen = Math.min(chunk.length - 1, msgLen - dataStream.size());
                dataStream.write(chunk, 1, copyLen);
            }

            return new MessageResponse(msgType, dataStream.toByteArray());
        } catch(Exception e) {
            throw new DeviceException("Error reading V1 message during probe", e);
        }
    }

    /**
     * Get message type ID from protobuf message.
     */
    private static int getMessageType(Message message) {
        String msgName = message.getClass().getSimpleName();
        if(msgName.startsWith("TxAck")) {
            msgName = "TxAck";
        }

        return TrezorMessage.MessageType.valueOf("MessageType_" + msgName).getNumber();
    }

    /**
     * Message response container for probing.
     */
    private static class MessageResponse {
        final int messageType;
        final byte[] messageBytes;

        MessageResponse(int messageType, byte[] messageBytes) {
            this.messageType = messageType;
            this.messageBytes = messageBytes;
        }
    }
}
