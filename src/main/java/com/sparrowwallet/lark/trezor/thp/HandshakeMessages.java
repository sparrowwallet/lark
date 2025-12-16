package com.sparrowwallet.lark.trezor.thp;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageThp;

/**
 * THP handshake message builders and parsers.
 *
 * Handles the THP-specific formatting of Noise handshake messages,
 * including the try_to_unlock flag and protobuf payloads.
 */
public class HandshakeMessages {

    /**
     * Pairing state returned in HandshakeCompletionResponse.
     */
    public enum PairingState {
        UNPAIRED(0x00),
        PAIRED(0x01),
        PAIRED_AUTOCONNECT(0x02);

        private final int value;

        PairingState(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static PairingState fromByte(byte b) throws DeviceException {
            int value = b & 0xFF;
            for(PairingState state : values()) {
                if(state.value == value) {
                    return state;
                }
            }

            throw new DeviceException("Unknown pairing state: 0x" + String.format("%02X", value));
        }
    }

    /**
     * Build HandshakeInitiationRequest message.
     *
     * The Noise message already contains encrypted try_to_unlock byte as payload.
     * Format: ephemeral_pubkey (32) + encrypted(try_to_unlock) (1 + 16 tag) = 49 bytes
     *
     * @param noiseMessage The complete Noise handshake message
     * @return Complete handshake initiation request
     */
    public static byte[] buildHandshakeInitiation(byte[] noiseMessage) {
        // The Noise message already contains everything - just return it
        return noiseMessage;
    }

    /**
     * Parse HandshakeInitiationResponse message.
     *
     * Format: trezor_ephemeral_pubkey (32) + encrypted_static (48) + tag (16) = 96 bytes
     *
     * @param message The received message
     * @return The Noise handshake message (for NoiseProtocolAdapter.readHandshakeResponse)
     * @throws DeviceException if message format is invalid
     */
    public static byte[] parseHandshakeInitiationResponse(byte[] message) throws DeviceException {
        if(message == null || message.length != 96) {
            throw new DeviceException("Handshake initiation response must be 96 bytes, got " + (message == null ? "null" : message.length));
        }
        // The entire message is the Noise handshake response
        // NoiseProtocolAdapter will handle decryption
        return message;
    }

    /**
     * Build HandshakeCompletionRequest message.
     *
     * Format: encrypted_host_static_pubkey (48) + encrypted_payload (variable)
     *
     * @param noiseMessage The Noise handshake message (already contains encrypted static key + payload)
     * @return Complete handshake completion request
     */
    public static byte[] buildHandshakeCompletion(byte[] noiseMessage) {
        // The Noise message already contains:
        // - Encrypted host static pubkey (48 bytes)
        // - Encrypted payload (variable)
        // No additional THP-specific fields needed
        return noiseMessage;
    }

    /**
     * Build HandshakeCompletionRequest payload (before Noise encryption).
     *
     * @param credential The pairing credential (may be null for first-time pairing)
     * @return Protobuf-encoded payload
     */
    public static byte[] buildHandshakeCompletionPayload(byte[] credential) {
        TrezorMessageThp.ThpHandshakeCompletionReqNoisePayload.Builder builder = TrezorMessageThp.ThpHandshakeCompletionReqNoisePayload.newBuilder();
        if(credential != null) {
            builder.setHostPairingCredential(ByteString.copyFrom(credential));
        }

        return builder.build().toByteArray();
    }

    /**
     * Parse HandshakeCompletionResponse message.
     *
     * Format: encrypted_trezor_state (17 bytes total = 1 byte state + 16 byte tag)
     *
     * @param message The received encrypted message
     * @return The Noise message for decryption
     * @throws DeviceException if message format is invalid
     */
    public static byte[] parseHandshakeCompletionResponse(byte[] message) throws DeviceException {
        if(message == null || message.length != 17) {
            throw new DeviceException("Handshake completion response must be 17 bytes, got " + (message == null ? "null" : message.length));
        }

        return message;
    }

    /**
     * Parse decrypted pairing state from HandshakeCompletionResponse.
     *
     * @param decryptedPayload The decrypted payload (1 byte state)
     * @return The pairing state
     * @throws DeviceException if payload is invalid
     */
    public static PairingState parsePairingState(byte[] decryptedPayload) throws DeviceException {
        if(decryptedPayload == null || decryptedPayload.length != 1) {
            throw new DeviceException("Pairing state payload must be 1 byte, got " + (decryptedPayload == null ? "null" : decryptedPayload.length));
        }

        return PairingState.fromByte(decryptedPayload[0]);
    }

    /**
     * Parse credential from HandshakeCompletionRequest payload (after Noise decryption).
     * Used by Trezor, not typically needed on host side.
     *
     * @param decryptedPayload The decrypted protobuf payload
     * @return The credential, or null if not present
     * @throws DeviceException if protobuf parsing fails
     */
    public static byte[] parseCredentialFromPayload(byte[] decryptedPayload) throws DeviceException {
        if(decryptedPayload == null || decryptedPayload.length == 0) {
            return null;
        }

        try {
            TrezorMessageThp.ThpHandshakeCompletionReqNoisePayload payload = TrezorMessageThp.ThpHandshakeCompletionReqNoisePayload.parseFrom(decryptedPayload);

            if(payload.hasHostPairingCredential()) {
                return payload.getHostPairingCredential().toByteArray();
            }

            return null;
        } catch(InvalidProtocolBufferException e) {
            throw new DeviceException("Failed to parse handshake completion payload", e);
        }
    }
}
