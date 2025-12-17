package com.sparrowwallet.lark.trezor.thp;

import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.bitbox02.noise.NamedProtocolHandshakeBuilder;
import com.sparrowwallet.lark.bitbox02.noise.NoiseHandshake;
import com.sparrowwallet.lark.bitbox02.noise.NoSuchPatternException;
import com.sparrowwallet.lark.bitbox02.noise.NoiseTransport;
import com.sparrowwallet.lark.trezor.CredentialMatcher;

import javax.crypto.AEADBadTagException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Adapter for THP Noise protocol operations.
 *
 * Implements Noise_XX_25519_AESGCM_SHA256 handshake pattern:
 * - Pattern: XX (mutual authentication, both parties unknown initially)
 * - Key Agreement: X25519 (Curve25519 DH)
 * - Cipher: AES-256-GCM
 * - Hash: SHA-256
 *
 * Handshake flow:
 * -> e
 * <- e, ee, s, es
 * -> s, se
 */
public class NoiseProtocolAdapter {

    private static final String THP_PROTOCOL_NAME = "Noise_XX_25519_AESGCM_SHA256";

    private final NoiseHandshake handshake;
    private final KeyPair hostStaticKeyPair;
    private NoiseTransport transport;

    /**
     * Create Noise protocol adapter for THP host (initiator role).
     *
     * @param prologue Device properties from ChannelAllocationResponse
     * @param hostStaticKeyPair Host's static key pair (may be null for first-time pairing)
     * @throws DeviceException if Noise initialization fails
     */
    public NoiseProtocolAdapter(byte[] prologue, KeyPair hostStaticKeyPair) throws DeviceException {
        this.hostStaticKeyPair = hostStaticKeyPair;

        try {
            // If no static key provided, generate one
            KeyPair staticKeys = hostStaticKeyPair;
            if(staticKeys == null) {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("X25519");
                staticKeys = keyGen.generateKeyPair();
            }

            // Build XX handshake as initiator
            NamedProtocolHandshakeBuilder builder = new NamedProtocolHandshakeBuilder(
                    THP_PROTOCOL_NAME,
                    NoiseHandshake.Role.INITIATOR
            );

            builder.setPrologue(prologue);
            builder.setLocalStaticKeyPair(staticKeys);

            this.handshake = builder.build();
        } catch(NoSuchAlgorithmException | NoSuchPatternException e) {
            throw new DeviceException("Failed to initialize Noise protocol: " + e.getMessage(), e);
        }
    }

    /**
     * Write first handshake message (-> e).
     * Host sends ephemeral public key with optional payload.
     *
     * @param payload Payload to encrypt (e.g., try_to_unlock byte)
     * @return HandshakeInitiationRequest message
     * @throws DeviceException if handshake operation fails
     */
    public byte[] writeHandshakeInitiation(byte[] payload) throws DeviceException {
        if(payload == null) {
            payload = new byte[0];
        }

        return handshake.writeMessage(payload);
    }

    /**
     * Read second handshake message (<- e, ee, s, es).
     * Trezor sends ephemeral pubkey + encrypted static pubkey (masked).
     *
     * @param message The received handshake message
     * @return Decrypted payload (empty for this message)
     * @throws DeviceException if decryption or verification fails
     */
    public byte[] readHandshakeResponse(byte[] message) throws DeviceException {
        try {
            return handshake.readMessage(message);
        } catch(AEADBadTagException e) {
            throw new DeviceException("Handshake authentication failed (initiation response). " +
                    "Message length: " + message.length + " bytes", e);
        } catch(Exception e) {
            throw new DeviceException("Error reading handshake initiation response: " + e.getMessage(), e);
        }
    }

    /**
     * Write third handshake message (-> s, se).
     * Host sends encrypted static pubkey.
     *
     * @param payload Optional encrypted payload (e.g., credential)
     * @return HandshakeCompletionRequest message
     * @throws DeviceException if handshake operation fails
     */
    public byte[] writeHandshakeCompletion(byte[] payload) throws DeviceException {
        if(payload == null) {
            payload = new byte[0];
        }

        return handshake.writeMessage(payload);
    }

    /**
     * Read fourth handshake message (<- final confirmation).
     * Trezor sends encrypted state (paired/unpaired status).
     *
     * @param message The received handshake message
     * @return Decrypted payload (pairing state)
     * @throws DeviceException if decryption or verification fails
     */
    public byte[] readHandshakeConfirmation(byte[] message) throws DeviceException {
        try {
            return handshake.readMessage(message);
        } catch(AEADBadTagException e) {
            throw new DeviceException("Handshake authentication failed", e);
        }
    }

    /**
     * Split the handshake into transport cipher states.
     * Call this after all handshake messages have been exchanged.
     *
     * @return Noise transport for encrypted communication
     * @throws DeviceException if handshake is not complete
     */
    public NoiseTransport split() throws DeviceException {
        if(!handshake.isDone()) {
            throw new DeviceException("Cannot split: handshake not complete");
        }

        this.transport = handshake.toTransport();
        return transport;
    }

    /**
     * Check if handshake is complete.
     */
    public boolean isHandshakeComplete() {
        return handshake.isDone();
    }

    /**
     * Get the host's static key pair (generated or provided).
     */
    public KeyPair getHostStaticKeyPair() {
        return hostStaticKeyPair;
    }

    /**
     * Update the host's static key pair mid-handshake.
     * Must be called after readHandshakeResponse() but before writeHandshakeCompletion().
     * Used when a matching credential is found with a different host key.
     *
     * @param newKeyPair The new host static key pair to use
     */
    public void updateHostStaticKeyPair(KeyPair newKeyPair) {
        handshake.setLocalStaticKeyPair(newKeyPair);
    }

    /**
     * Get the transport (only available after split()).
     */
    public NoiseTransport getTransport() {
        return transport;
    }

    /**
     * Get Trezor's public keys for credential matching.
     * Only available after reading the 2nd handshake message (handshake initiation response).
     *
     * @return Trezor's ephemeral and static public keys
     * @throws DeviceException if keys are not available
     */
    public CredentialMatcher.TrezorPublicKeys getTrezorPublicKeys() throws DeviceException {
        // Get remote ephemeral public key (re)
        java.security.PublicKey remoteEphemeral = handshake.getRemoteEphemeralPublicKey();

        // Get remote static public key (rs)
        java.security.PublicKey remoteStatic = handshake.getRemoteStaticPublicKey();

        if(remoteEphemeral == null || remoteStatic == null) {
            throw new DeviceException("Trezor public keys not yet available from handshake");
        }

        // Extract raw 32-byte keys
        byte[] ephemeralRaw = extractRawPublicKey(remoteEphemeral);
        byte[] staticRaw = extractRawPublicKey(remoteStatic);

        return new CredentialMatcher.TrezorPublicKeys(ephemeralRaw, staticRaw);
    }

    /**
     * Get the remote (Trezor's) static public key.
     * Only available after handshake is complete.
     *
     * @return Trezor's static public key
     * @throws DeviceException if handshake is not complete
     */
    public byte[] getRemoteStaticPublicKey() throws DeviceException {
        if(!handshake.isDone()) {
            throw new DeviceException("Cannot get remote static key: handshake not complete");
        }

        java.security.PublicKey remotePublicKey = handshake.getRemoteStaticPublicKey();
        if(remotePublicKey == null) {
            throw new DeviceException("Remote static public key not available");
        }

        return extractRawPublicKey(remotePublicKey);
    }

    /**
     * Extract raw 32-byte public key from X.509 encoded key.
     */
    private byte[] extractRawPublicKey(java.security.PublicKey publicKey) {
        byte[] encoded = publicKey.getEncoded();
        // X.509 encoding: prefix (12 bytes) + raw key (32 bytes)
        byte[] rawKey = new byte[32];
        System.arraycopy(encoded, 12, rawKey, 0, 32);
        return rawKey;
    }

    /**
     * Get the Noise handshake hash.
     * Only available after handshake is complete.
     * Used for CPace pairing verification.
     *
     * @return Handshake hash (32 bytes)
     * @throws DeviceException if handshake is not complete
     */
    public byte[] getHandshakeHash() throws DeviceException {
        if(!handshake.isDone()) {
            throw new DeviceException("Cannot get handshake hash: handshake not complete");
        }

        return handshake.getHash();
    }
}
