package com.sparrowwallet.lark.trezor.thp;

import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.bitbox02.noise.NoiseTransport;
import com.sparrowwallet.lark.trezor.CredentialMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.AEADBadTagException;
import java.security.KeyPair;

/**
 * THP handshake state machine.
 *
 * Implements the host-side handshake protocol (states HH0 → HH1 → HH2/HH3 → completion).
 * Coordinates Noise protocol operations with THP-specific message formatting.
 *
 * Handshake flow:
 * 1. HH0: Send HandshakeInitiationRequest (host ephemeral pubkey + try_to_unlock)
 * 2. HH1: Receive HandshakeInitiationResponse (trezor ephemeral + encrypted static)
 * 3. HH2/HH3: Send HandshakeCompletionRequest (encrypted host static + credential)
 * 4. Receive HandshakeCompletionResponse (encrypted pairing state)
 * 5. Complete: Transition to HC1 or HP0 based on pairing state
 */
public class HandshakeStateMachine {
    private static final Logger log = LoggerFactory.getLogger(HandshakeStateMachine.class);

    /**
     * Host handshake states.
     */
    public enum State {
        HH0,  // Initial - ready to send initiation
        HH1,  // Awaiting initiation response
        HH2,  // Ready to send completion with credential
        HH3,  // Ready to send completion without credential
        COMPLETE  // Handshake complete
    }

    /**
     * Handshake result.
     */
    public static class Result {
        public final int channelId;
        public final HandshakeMessages.PairingState pairingState;
        public final NoiseTransport transport;
        public final KeyPair hostStaticKeyPair;
        public final byte[] trezorStaticPubkey;
        public final byte[] handshakeHash;

        public Result(int channelId, HandshakeMessages.PairingState pairingState, NoiseTransport transport, KeyPair hostStaticKeyPair, byte[] trezorStaticPubkey, byte[] handshakeHash) {
            this.channelId = channelId;
            this.pairingState = pairingState;
            this.transport = transport;
            this.hostStaticKeyPair = hostStaticKeyPair;
            this.trezorStaticPubkey = trezorStaticPubkey;
            this.handshakeHash = handshakeHash;
        }
    }

    /**
     * Message exchange interface for handshake communication.
     */
    public interface MessageExchange {
        /**
         * Send handshake initiation request and receive response.
         *
         * @param request The handshake initiation request (33 bytes)
         * @return The handshake initiation response (96 bytes)
         * @throws DeviceException if communication fails
         */
        byte[] exchangeInitiation(byte[] request) throws DeviceException;

        /**
         * Find matching credential from available credentials.
         * Called after receiving initiation response, before sending completion request.
         *
         * @param trezorKeys Trezor's ephemeral and static public keys from handshake
         * @return Matching credential, or null if no match
         * @throws DeviceException if credential search fails
         */
        CredentialMatcher.StoredCredential findCredential(CredentialMatcher.TrezorPublicKeys trezorKeys) throws DeviceException;

        /**
         * Send handshake completion request and receive response.
         *
         * @param request The handshake completion request (variable length)
         * @return The handshake completion response (17 bytes) and allocated channel ID
         * @throws DeviceException if communication fails
         */
        CompletionResponse exchangeCompletion(byte[] request) throws DeviceException;
    }

    /**
     * Handshake completion response with channel ID.
     */
    public static class CompletionResponse {
        public final int channelId;
        public final byte[] response;

        public CompletionResponse(int channelId, byte[] response) {
            this.channelId = channelId;
            this.response = response;
        }
    }

    private final NoiseProtocolAdapter noiseAdapter;
    private final byte[] credential;
    private final boolean tryToUnlock;
    private State state;

    /**
     * Create handshake state machine.
     *
     * @param prologue Device properties from ChannelAllocationResponse
     * @param hostStaticKeyPair Host's static key pair (may be null for first-time pairing)
     * @param credential Pairing credential (may be null for first-time pairing)
     * @param tryToUnlock Whether to attempt unlocking the device
     * @throws DeviceException if Noise initialization fails
     */
    public HandshakeStateMachine(byte[] prologue, KeyPair hostStaticKeyPair, byte[] credential, boolean tryToUnlock) throws DeviceException {
        this.noiseAdapter = new NoiseProtocolAdapter(prologue, hostStaticKeyPair);
        this.credential = credential;
        this.tryToUnlock = tryToUnlock;
        this.state = State.HH0;
    }

    /**
     * Execute the complete handshake protocol.
     *
     * @param exchange Message exchange implementation
     * @return Handshake result with channel ID, pairing state, and transport
     * @throws DeviceException if handshake fails
     */
    public Result executeHandshake(MessageExchange exchange) throws DeviceException {
        // HH0 → HH1: Send initiation request
        if(state != State.HH0) {
            throw new DeviceException("Invalid state for handshake initiation: " + state);
        }

        // Pass try_to_unlock as encrypted payload to Noise
        byte[] unlockPayload = new byte[] { tryToUnlock ? (byte)0x01 : (byte)0x00 };
        byte[] noiseInitiation = noiseAdapter.writeHandshakeInitiation(unlockPayload);
        if(log.isDebugEnabled()) {
            log.debug("Noise initiation message: {} bytes (includes encrypted try_to_unlock)", noiseInitiation.length);
        }
        byte[] initiationRequest = HandshakeMessages.buildHandshakeInitiation(noiseInitiation);
        if(log.isDebugEnabled()) {
            log.debug("Sending HandshakeInitiationRequest: {} bytes", initiationRequest.length);
        }
        state = State.HH1;

        // HH1 → HH2/HH3: Receive initiation response
        byte[] initiationResponse = exchange.exchangeInitiation(initiationRequest);
        if(log.isDebugEnabled()) {
            log.debug("Received HandshakeInitiationResponse: {} bytes", initiationResponse.length);
        }
        byte[] noiseResponse = HandshakeMessages.parseHandshakeInitiationResponse(initiationResponse);
        if(log.isDebugEnabled()) {
            log.debug("Noise response message: {} bytes", noiseResponse.length);
        }
        noiseAdapter.readHandshakeResponse(noiseResponse);

        // After receiving 2nd message, extract Trezor's public keys and find matching credential
        CredentialMatcher.TrezorPublicKeys trezorKeys = noiseAdapter.getTrezorPublicKeys();
        CredentialMatcher.StoredCredential matchedCred = exchange.findCredential(trezorKeys);

        byte[] credentialToUse;
        if(matchedCred != null) {
            // Found a matching credential - use its credential blob and host private key
            credentialToUse = matchedCred.credentialBlob;

            if(log.isDebugEnabled()) {
                log.debug("Using matched credential blob ({} bytes)", credentialToUse.length);
            }

            // Update the Noise handshake to use the matched credential's host key
            // (The host key must match the one that was paired with this credential)
            try {
                java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("X25519");

                // Convert raw 32-byte private key to PrivateKey
                byte[] pkcs8 = new byte[48];
                byte[] header = {
                    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
                };
                System.arraycopy(header, 0, pkcs8, 0, 16);
                System.arraycopy(matchedCred.hostPrivateKey, 0, pkcs8, 16, 32);

                java.security.spec.PKCS8EncodedKeySpec privateKeySpec =
                    new java.security.spec.PKCS8EncodedKeySpec(pkcs8);
                java.security.PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

                // Derive public key from private key using scalar multiplication with base point
                // X25519 base point (generator)
                byte[] basepoint = new byte[32];
                basepoint[0] = 9;

                byte[] publicKeyRaw = x25519ScalarMult(matchedCred.hostPrivateKey, basepoint);

                // Convert raw public key to PublicKey
                byte[] x509 = new byte[44];
                byte[] pubHeader = {
                    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
                };
                System.arraycopy(pubHeader, 0, x509, 0, 12);
                System.arraycopy(publicKeyRaw, 0, x509, 12, 32);

                java.security.PublicKey publicKey = keyFactory.generatePublic(
                    new java.security.spec.X509EncodedKeySpec(x509)
                );

                KeyPair matchedKeyPair = new KeyPair(publicKey, privateKey);
                noiseAdapter.updateHostStaticKeyPair(matchedKeyPair);

                if(log.isDebugEnabled()) {
                    log.debug("Updated handshake to use matched credential's host key");
                }
            } catch(Exception e) {
                throw new DeviceException("Failed to update host key for matched credential: " + e.getMessage(), e);
            }
        } else {
            // No matching credential - use the one provided to constructor (may be null)
            credentialToUse = credential;
        }

        // Determine next state based on credential availability
        state = (credentialToUse != null) ? State.HH2 : State.HH3;

        // HH2/HH3 → Complete: Send completion request
        byte[] completionPayload = HandshakeMessages.buildHandshakeCompletionPayload(credentialToUse);
        byte[] noiseCompletion = noiseAdapter.writeHandshakeCompletion(completionPayload);
        byte[] completionRequest = HandshakeMessages.buildHandshakeCompletion(noiseCompletion);

        // Extract Trezor's static public key (must be done before split)
        byte[] trezorStaticPubkey = noiseAdapter.getRemoteStaticPublicKey();

        // Split handshake into transport AFTER 3rd message (Noise XX pattern complete)
        NoiseTransport transport = noiseAdapter.split();

        // Extract handshake hash AFTER split (used for CPace pairing verification)
        byte[] handshakeHash = noiseAdapter.getHandshakeHash();

        // Receive completion response with channel ID
        // NOTE: This 4th THP message is NOT part of Noise handshake - it's encrypted with transport cipher
        CompletionResponse completionResponse = exchange.exchangeCompletion(completionRequest);
        byte[] encryptedState = HandshakeMessages.parseHandshakeCompletionResponse(completionResponse.response);

        // Decrypt using transport cipher (not handshake)
        byte[] pairingStateBytes;
        try {
            pairingStateBytes = transport.readMessage(encryptedState);
        } catch(AEADBadTagException e) {
            throw new DeviceException("Failed to decrypt handshake completion response", e);
        }

        // Parse pairing state
        HandshakeMessages.PairingState pairingState = HandshakeMessages.parsePairingState(pairingStateBytes);

        state = State.COMPLETE;

        return new Result(
            completionResponse.channelId,
            pairingState,
            transport,
            noiseAdapter.getHostStaticKeyPair(),
            trezorStaticPubkey,
            handshakeHash
        );
    }

    /**
     * Get current state.
     */
    public State getState() {
        return state;
    }

    /**
     * Check if handshake is complete.
     */
    public boolean isComplete() {
        return state == State.COMPLETE;
    }

    /**
     * Perform X25519 scalar multiplication: scalar * point.
     */
    private byte[] x25519ScalarMult(byte[] scalar, byte[] point) throws java.security.GeneralSecurityException {
        javax.crypto.KeyAgreement keyAgreement = javax.crypto.KeyAgreement.getInstance("X25519");
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("X25519");

        // Create PrivateKey from scalar
        byte[] pkcs8 = new byte[48];
        byte[] header = {
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
        };
        System.arraycopy(header, 0, pkcs8, 0, 16);
        System.arraycopy(scalar, 0, pkcs8, 16, 32);
        java.security.PrivateKey privateKey = keyFactory.generatePrivate(
            new java.security.spec.PKCS8EncodedKeySpec(pkcs8)
        );

        // Create PublicKey from point
        byte[] x509 = new byte[44];
        byte[] pubHeader = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
        };
        System.arraycopy(pubHeader, 0, x509, 0, 12);
        System.arraycopy(point, 0, x509, 12, 32);
        java.security.PublicKey publicKey = keyFactory.generatePublic(
            new java.security.spec.X509EncodedKeySpec(x509)
        );

        // Perform key agreement
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }
}
