package com.sparrowwallet.lark.trezor.thp;

import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.bitbox02.noise.NoiseTransport;
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

        public Result(int channelId, HandshakeMessages.PairingState pairingState, NoiseTransport transport, KeyPair hostStaticKeyPair, byte[] trezorStaticPubkey) {
            this.channelId = channelId;
            this.pairingState = pairingState;
            this.transport = transport;
            this.hostStaticKeyPair = hostStaticKeyPair;
            this.trezorStaticPubkey = trezorStaticPubkey;
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

        // Determine next state based on credential availability
        state = (credential != null) ? State.HH2 : State.HH3;

        // HH2/HH3 → Complete: Send completion request
        byte[] completionPayload = HandshakeMessages.buildHandshakeCompletionPayload(credential);
        byte[] noiseCompletion = noiseAdapter.writeHandshakeCompletion(completionPayload);
        byte[] completionRequest = HandshakeMessages.buildHandshakeCompletion(noiseCompletion);

        // Extract Trezor's static public key (must be done before split)
        byte[] trezorStaticPubkey = noiseAdapter.getRemoteStaticPublicKey();

        // Split handshake into transport AFTER 3rd message (Noise XX pattern complete)
        NoiseTransport transport = noiseAdapter.split();

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
            trezorStaticPubkey
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
}
