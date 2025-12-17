package com.sparrowwallet.lark.trezor;

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.UserRefusedException;
import com.sparrowwallet.lark.trezor.generated.TrezorMessage;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageBitcoin;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageCommon;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageManagement;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageThp;
import com.sparrowwallet.lark.trezor.thp.*;
import com.sparrowwallet.lark.trezor.thp.cpace.CPace;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;
import java.security.KeyPair;
import java.util.List;
import java.text.Normalizer;

/**
 * THP (Trezor Host Protocol) v2 implementation.
 *
 * Implements encrypted communication using Noise_XX_25519_AESGCM_SHA256.
 * Handles channel allocation, handshake, and encrypted message exchange.
 */
class V2Protocol implements Protocol {
    private static final Logger log = LoggerFactory.getLogger(V2Protocol.class);

    private static final int MAX_PASSPHRASE_LENGTH = 50;
    private static final int MAX_PIN_LENGTH = 50;

    private final Transport transport;
    private final TrezorUI ui;
    private final ProtocolCallbacks callbacks;
    private final TrezorNoiseConfig credentialStore;

    // THP session state
    private EncryptedTransport encryptedTransport;
    private HandshakeMessages.PairingState pairingState;
    private KeyPair hostStaticKeyPair;
    private byte[] trezorStaticPubkey;
    private byte[] handshakeHash;
    private boolean initialized;

    /**
     * Create V2 protocol instance with credential store.
     *
     * The credential store is used to persist pairing credentials across sessions.
     * If no credential exists for the device, a new pairing will be performed.
     *
     * @param transport The underlying transport (USB, etc.)
     * @param ui User interaction callbacks
     * @param callbacks Protocol callbacks for device communication
     * @param credentialStore Credential storage for pairing persistence
     */
    V2Protocol(Transport transport, TrezorUI ui, ProtocolCallbacks callbacks, TrezorNoiseConfig credentialStore) {
        this.transport = transport;
        this.ui = ui;
        this.callbacks = callbacks;
        this.credentialStore = credentialStore != null ? credentialStore : new TrezorFileNoiseConfig();
        this.initialized = false;
    }

    @Override
    public <T extends Message> T call(Message message, Class<T> toValueType) throws DeviceException {
        ensureInitialized();

        Message response = callRaw(message);

        while(true) {
            if(response instanceof TrezorMessageCommon.PinMatrixRequest pinMatrixRequest) {
                response = callbackPin(pinMatrixRequest);
            } else if(response instanceof TrezorMessageCommon.PassphraseRequest passphraseRequest) {
                response = callbackPassphrase(passphraseRequest);
            } else if(response instanceof TrezorMessageCommon.ButtonRequest buttonRequest) {
                response = callbackButton(buttonRequest);
            } else if(response instanceof TrezorMessageCommon.Failure failure) {
                if(failure.getCode() == TrezorMessageCommon.Failure.FailureType.Failure_ActionCancelled) {
                    throw new UserRefusedException(failure.getMessage());
                }
                throw new DeviceException(failure.getMessage());
            } else {
                return toValueType.cast(response);
            }
        }
    }

    @Override
    public Message callRaw(Message message) throws DeviceException {
        ensureInitialized();

        sendMessage(message);
        return receiveMessage();
    }

    @Override
    public void close() {
        try {
            transport.close();
        } catch(Exception e) {
            log.warn("Error closing transport", e);
        }
    }

    // ===== Initialization =====

    /**
     * Ensure THP session is initialized (channel allocated and handshake complete).
     */
    private void ensureInitialized() throws DeviceException {
        if(initialized) {
            return;
        }

        if(log.isDebugEnabled()) {
            log.debug("Initializing THP session...");
        }

        // Step 1: Allocate channel
        ChannelAllocator allocator = new ChannelAllocator(transport);
        ChannelAllocationMessages.AllocationResponse allocationResponse = allocator.allocateChannel(ChannelAllocationMessages.PROTOCOL_VERSION_V1);

        if(log.isDebugEnabled()) {
            log.debug("Channel allocated: 0x{}", String.format("%04X", allocationResponse.channelId));
        }

        // Step 2: Load or generate host static key pair
        this.hostStaticKeyPair = loadOrGenerateHostStaticKey();

        // Step 3: Perform handshake (credential matching happens inside)
        HandshakeStateMachine.Result handshakeResult = performHandshake(
                allocationResponse.channelId,
                allocationResponse.devicePropertiesBytes,
                null // credentials will be searched during handshake
        );

        // Step 4: Extract Trezor's static public key and handshake hash from handshake result
        this.trezorStaticPubkey = handshakeResult.trezorStaticPubkey;
        this.handshakeHash = handshakeResult.handshakeHash;

        // Step 5: Create encrypted transport
        this.encryptedTransport = new EncryptedTransport(
                transport,
                handshakeResult.transport,
                handshakeResult.channelId
        );
        this.pairingState = handshakeResult.pairingState;

        // Step 7: Save host static key
        saveHostStaticKey();

        // Step 8: Mark as initialized BEFORE pairing
        // (pairing will call callRaw which needs initialized=true to avoid infinite loop)
        this.initialized = true;

        // Step 9: Handle pairing state
        if(pairingState == HandshakeMessages.PairingState.UNPAIRED) {
            if(log.isDebugEnabled()) {
                log.debug("Device is UNPAIRED - initiating pairing flow");
            }

            // Perform pairing and obtain credential
            // This will send ThpEndRequest at the end
            performPairing();

            if(log.isDebugEnabled()) {
                log.debug("Pairing completed successfully");
            }
        } else {
            // Device is already paired (PAIRED or PAIRED_AUTOCONNECT)
            if(log.isDebugEnabled()) {
                log.debug("Device pairing state: {}", pairingState);
            }

            // Send ThpEndRequest to close the handshake session
            // This is required even for PAIRED_AUTOCONNECT (Python ref does this)
            if(log.isDebugEnabled()) {
                log.debug("Ending handshake session");
            }
            TrezorMessageThp.ThpEndRequest endRequest =
                    TrezorMessageThp.ThpEndRequest.newBuilder()
                            .build();
            call(endRequest, TrezorMessageThp.ThpEndResponse.class);
        }

        if(log.isDebugEnabled()) {
            log.debug("THP session initialized (pairing state: {})", pairingState);
        }
    }

    /**
     * Load host static key from credential store, or generate a new one.
     */
    private KeyPair loadOrGenerateHostStaticKey() throws DeviceException {
        try {
            // Try to load existing host static key
            java.util.Optional<byte[]> existingKey = credentialStore.getHostStaticPrivateKey();
            if(existingKey.isPresent()) {
                if(log.isDebugEnabled()) {
                    log.debug("Loaded existing host static key from credential store");
                }

                // Convert raw private key bytes to KeyPair
                byte[] privateKeyBytes = existingKey.get();
                java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("X25519");

                // Create private key from raw bytes
                byte[] encoded = new byte[48]; // PKCS#8 prefix (16 bytes) + key (32 bytes)
                System.arraycopy(new byte[] {
                    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
                }, 0, encoded, 0, 16);
                System.arraycopy(privateKeyBytes, 0, encoded, 16, 32);

                java.security.spec.PKCS8EncodedKeySpec privateKeySpec =
                    new java.security.spec.PKCS8EncodedKeySpec(encoded);
                java.security.PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

                // Derive public key from private key using X25519 scalar multiplication with base point
                byte[] basepoint = new byte[32];
                basepoint[0] = 9; // X25519 base point (generator)

                byte[] publicKeyRaw = x25519ScalarMult(privateKeyBytes, basepoint);

                // Convert raw public key to PublicKey object
                byte[] x509 = new byte[44];
                byte[] pubHeader = {
                    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
                };
                System.arraycopy(pubHeader, 0, x509, 0, 12);
                System.arraycopy(publicKeyRaw, 0, x509, 12, 32);

                java.security.PublicKey publicKey = keyFactory.generatePublic(
                    new java.security.spec.X509EncodedKeySpec(x509)
                );

                return new KeyPair(publicKey, privateKey);
            }

            // Generate new key pair
            if(log.isDebugEnabled()) {
                log.debug("Generating new host static key pair");
            }
            java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("X25519");
            return keyGen.generateKeyPair();

        } catch(Exception e) {
            throw new DeviceException("Failed to load or generate host static key", e);
        }
    }

    /**
     * Save host static key to credential store.
     */
    private void saveHostStaticKey() {
        if(hostStaticKeyPair == null) {
            return;
        }

        try {
            // Extract raw private key bytes
            byte[] encoded = hostStaticKeyPair.getPrivate().getEncoded();

            // Remove PKCS#8 prefix (16 bytes) to get raw 32-byte private key
            byte[] privateKeyBytes = new byte[32];
            System.arraycopy(encoded, 16, privateKeyBytes, 0, 32);

            credentialStore.setHostStaticPrivateKey(privateKeyBytes);

            if(log.isDebugEnabled()) {
                log.debug("Saved host static key to credential store");
            }
        } catch(Exception e) {
            log.error("Failed to save host static key", e);
        }
    }

    /**
     * Perform pairing flow to obtain credential.
     * Must be called with an active encrypted transport.
     */
    private void performPairing() throws DeviceException {
        try {
            // Get device info for UI
            String deviceInfo = "Trezor device"; // TODO: Extract from Features message

            // Step 1: Ask user to confirm pairing
            boolean confirmed = credentialStore.confirmPairing(deviceInfo);
            if(!confirmed) {
                throw new UserRefusedException("User declined pairing request");
            }

            // Step 2: Send PairingRequest
            if(log.isDebugEnabled()) {
                log.debug("Sending ThpPairingRequest");
            }

            TrezorMessageThp.ThpPairingRequest pairingRequest =
                    TrezorMessageThp.ThpPairingRequest.newBuilder()
                            .setHostName(credentialStore.getHostName())
                            .setAppName(credentialStore.getAppName())
                            .build();

            // Step 3: Expect PairingRequestApproved
            TrezorMessageThp.ThpPairingRequestApproved pairingApproved = call(pairingRequest, TrezorMessageThp.ThpPairingRequestApproved.class);

            if(log.isDebugEnabled()) {
                log.debug("Received ThpPairingRequestApproved");
            }

            // Step 4: Select pairing method (Code Entry)
            // TODO: Allow user to select method if multiple are available
            TrezorMessageThp.ThpSelectMethod selectMethod =
                    TrezorMessageThp.ThpSelectMethod.newBuilder()
                            .setSelectedPairingMethod(TrezorMessageThp.ThpPairingMethod.CodeEntry)
                            .build();

            Message response = call(selectMethod, Message.class);

            // Step 5: Perform Code Entry pairing
            performCodeEntryPairing(response);

            // Step 6: Request credential
            requestAndStoreCredential();

            // Step 7: End pairing session
            // This properly closes the pairing session so session 0 can be reused normally
            if(log.isDebugEnabled()) {
                log.debug("Ending pairing session");
            }
            TrezorMessageThp.ThpEndRequest endRequest =
                    TrezorMessageThp.ThpEndRequest.newBuilder()
                            .build();
            call(endRequest, TrezorMessageThp.ThpEndResponse.class);

            // Step 8: Create session 0 for normal operations
            // After pairing + ThpEndRequest, we need to establish session 0
            if(log.isDebugEnabled()) {
                log.debug("Creating session 0 after pairing");
            }
            TrezorMessageThp.ThpCreateNewSession createSession =
                    TrezorMessageThp.ThpCreateNewSession.newBuilder()
                            .build();
            call(createSession, TrezorMessageCommon.Success.class);

            // Step 9: Update pairing state to reflect successful pairing
            // The device is now paired, even though initial handshake showed UNPAIRED
            this.pairingState = HandshakeMessages.PairingState.PAIRED;

            if(log.isDebugEnabled()) {
                log.debug("Pairing state updated to PAIRED");
            }

            // Notify success
            credentialStore.pairingSuccessful(deviceInfo);

        } catch(DeviceException e) {
            credentialStore.pairingFailed(e.getMessage());
            throw e;
        }
    }

    /**
     * Perform Code Entry pairing method.
     */
    private void performCodeEntryPairing(Message initialResponse) throws DeviceException {
        // Step 1: Expect CodeEntryCommitment
        if(!(initialResponse instanceof TrezorMessageThp.ThpCodeEntryCommitment commitment)) {
            throw new DeviceException("Expected ThpCodeEntryCommitment, got " + initialResponse.getClass().getSimpleName());
        }

        byte[] commitmentBytes = commitment.getCommitment().toByteArray();
        if(log.isDebugEnabled()) {
            log.debug("Received CodeEntryCommitment: {}", Utils.bytesToHex(commitmentBytes));
        }

        // Step 2: Generate random challenge (16 bytes)
        byte[] challenge = new byte[16];
        new java.security.SecureRandom().nextBytes(challenge);

        if(log.isDebugEnabled()) {
            log.debug("Sending CodeEntryChallenge: {}", Utils.bytesToHex(challenge));
        }

        TrezorMessageThp.ThpCodeEntryChallenge challengeMsg =
                TrezorMessageThp.ThpCodeEntryChallenge.newBuilder()
                        .setChallenge(com.google.protobuf.ByteString.copyFrom(challenge))
                        .build();

        // Step 3: Expect CodeEntryCpaceTrezor
        TrezorMessageThp.ThpCodeEntryCpaceTrezor cpaceTrezor =
                call(challengeMsg, TrezorMessageThp.ThpCodeEntryCpaceTrezor.class);

        byte[] trezorPublicKey = cpaceTrezor.getCpaceTrezorPublicKey().toByteArray();
        if(log.isDebugEnabled()) {
            log.debug("Received CodeEntryCpaceTrezor public key: {}", Utils.bytesToHex(trezorPublicKey));
        }

        // Step 4: Prompt user for pairing code
        String pairingCode = credentialStore.promptForPairingCode();
        if(log.isDebugEnabled()) {
            log.debug("User entered pairing code: {}", pairingCode);
        }

        // Step 5: Perform CPace calculation
        CPace.Result cpaceResult;
        try {
            cpaceResult = CPace.calculate(pairingCode, handshakeHash, trezorPublicKey);
            if(log.isDebugEnabled()) {
                log.debug("CPace calculation complete");
            }
        } catch(Exception e) {
            throw new DeviceException("CPace calculation failed: " + e.getMessage(), e);
        }

        byte[] hostPublicKey = cpaceResult.hostPublicKey;
        byte[] tag = cpaceResult.tag;

        if(log.isDebugEnabled()) {
            log.debug("Sending CodeEntryCpaceHostTag");
        }

        TrezorMessageThp.ThpCodeEntryCpaceHostTag hostTag =
                TrezorMessageThp.ThpCodeEntryCpaceHostTag.newBuilder()
                        .setCpaceHostPublicKey(com.google.protobuf.ByteString.copyFrom(hostPublicKey))
                        .setTag(com.google.protobuf.ByteString.copyFrom(tag))
                        .build();

        // Step 6: Expect CodeEntrySecret
        TrezorMessageThp.ThpCodeEntrySecret secret =
                call(hostTag, TrezorMessageThp.ThpCodeEntrySecret.class);

        byte[] secretBytes = secret.getSecret().toByteArray();
        if(log.isDebugEnabled()) {
            log.debug("Received CodeEntrySecret: {}", Utils.bytesToHex(secretBytes));
        }

        // Step 7: Verify commitment using Sha256Hash
        byte[] computedCommitment = Sha256Hash.hash(secretBytes);
        if(!java.util.Arrays.equals(computedCommitment, commitmentBytes)) {
            throw new DeviceException("Commitment verification failed - possible MITM attack");
        }

        if(log.isDebugEnabled()) {
            log.debug("Commitment verified successfully");
        }

        // Step 8: Verify pairing code matches derived value
        String derivedCode = CPace.deriveCode(secretBytes, handshakeHash, challenge);
        if(!derivedCode.equals(pairingCode)) {
            throw new DeviceException("Pairing code mismatch - expected " + derivedCode +
                                    " but user entered " + pairingCode);
        }

        if(log.isDebugEnabled()) {
            log.debug("Pairing code verified successfully");
        }
    }

    /**
     * Request credential from device and store it.
     */
    private void requestAndStoreCredential() throws DeviceException {
        // Get host static public key
        byte[] hostStaticPubkey = hostStaticKeyPair.getPublic().getEncoded();
        // Remove X.509 header (12 bytes for X25519) to get raw 32-byte public key
        byte[] rawHostPubkey = new byte[32];
        System.arraycopy(hostStaticPubkey, hostStaticPubkey.length - 32, rawHostPubkey, 0, 32);

        if(log.isDebugEnabled()) {
            log.debug("Requesting credential with host public key: {}", Utils.bytesToHex(rawHostPubkey));
        }

        TrezorMessageThp.ThpCredentialRequest credRequest =
                TrezorMessageThp.ThpCredentialRequest.newBuilder()
                        .setHostStaticPublicKey(com.google.protobuf.ByteString.copyFrom(rawHostPubkey))
                        .setAutoconnect(false)  // Initial pairing requires false; device transitions to autoconnect later
                        .build();

        TrezorMessageThp.ThpCredentialResponse credResponse =
                call(credRequest, TrezorMessageThp.ThpCredentialResponse.class);

        byte[] credentialBlob = credResponse.getCredential().toByteArray();
        byte[] trezorPubkeyFromResponse = credResponse.getTrezorStaticPublicKey().toByteArray();

        if(log.isDebugEnabled()) {
            log.debug("Received credential ({} bytes): {}", credentialBlob.length, Utils.bytesToHex(credentialBlob));
            log.debug("Trezor pubkey from response: {}", Utils.bytesToHex(trezorPubkeyFromResponse));
        }

        // Store credential using Trezor pubkey from CredentialResponse (not from handshake!)
        // This is the key used for credential matching during reconnection
        credentialStore.addCredential(trezorPubkeyFromResponse, credentialBlob);
        if(log.isDebugEnabled()) {
            log.debug("Credential stored for device");
        }
    }

    /**
     * Perform THP handshake on allocated channel.
     */
    private HandshakeStateMachine.Result performHandshake(int channelId, byte[] prologue, byte[] credential)
            throws DeviceException {

        HandshakeStateMachine stateMachine = new HandshakeStateMachine(
                prologue,
                hostStaticKeyPair,
                credential,
                true // tryToUnlock - unlock device if locked
        );

        // Create message exchange adapter for handshake
        HandshakeStateMachine.MessageExchange exchange = new HandshakeStateMachine.MessageExchange() {
            @Override
            public byte[] exchangeInitiation(byte[] request) throws DeviceException {
                // Handshake uses the allocated channel, not broadcast
                return sendAndReceiveHandshake(request, channelId,
                        ControlByte.PacketType.HANDSHAKE_INIT_RESP);
            }

            @Override
            public CredentialMatcher.StoredCredential findCredential(CredentialMatcher.TrezorPublicKeys trezorKeys) throws DeviceException {
                // Get all stored credentials
                List<CredentialMatcher.StoredCredential> credentials = credentialStore.getAllCredentials();

                if(credentials.isEmpty()) {
                    if(log.isDebugEnabled()) {
                        log.debug("No stored credentials to search");
                    }
                    return null;
                }

                if(log.isDebugEnabled()) {
                    log.debug("Searching {} stored credential(s) for match", credentials.size());
                }

                // Find matching credential
                CredentialMatcher.StoredCredential match = CredentialMatcher.findCredential(credentials, trezorKeys);

                if(match != null) {
                    if(log.isDebugEnabled()) {
                        log.debug("Found matching credential for device");
                    }
                    return match;
                } else {
                    if(log.isDebugEnabled()) {
                        log.debug("No matching credential found for device");
                    }
                    return null;
                }
            }

            @Override
            public HandshakeStateMachine.CompletionResponse exchangeCompletion(byte[] request)
                    throws DeviceException {
                byte[] response = sendAndReceiveHandshake(request, channelId,
                        ControlByte.PacketType.HANDSHAKE_COMP_RESP);
                return new HandshakeStateMachine.CompletionResponse(channelId, response);
            }
        };

        return stateMachine.executeHandshake(exchange);
    }

    /**
     * Send handshake message and receive response.
     */
    private byte[] sendAndReceiveHandshake(byte[] payload, int channelId, ControlByte.PacketType expectedResponseType) throws DeviceException {

        // Determine control byte based on expected response
        // Per THP spec, handshake messages have FIXED sequence bits:
        // INIT_REQ/RESP: seq=0, COMP_REQ/RESP: seq=1
        byte controlByte;
        boolean isInitiation = (expectedResponseType == ControlByte.PacketType.HANDSHAKE_INIT_RESP);
        if(isInitiation) {
            controlByte = ControlByte.createHandshakeInitReq(false, false);  // seq=0, ack=0
        } else {
            controlByte = ControlByte.createHandshakeCompReq(true, false);   // seq=1, ack=0
        }

        // Send handshake message
        for(byte[] packet : PacketCodec.segment(controlByte, channelId, payload)) {
            transport.write(packet);
        }

        // ABP: After sending, we receive an ACK for our message
        byte[] ackPacket = transport.read();
        if(ackPacket == null || ackPacket.length != 64) {
            throw new DeviceException("Invalid ACK packet");
        }
        ControlByte.PacketType ackType = ControlByte.getPacketType(ackPacket[0]);
        boolean ackBit = ControlByte.getAckBit(ackPacket[0]);
        boolean seqBit = ControlByte.getSequenceBit(ackPacket[0]);
        if(log.isDebugEnabled()) {
            log.debug("Received after sending request: type={}, seq={}, ack={}, control_byte=0x{}",
                    ackType, seqBit, ackBit, String.format("%02X", ackPacket[0] & 0xFF));
        }

        // Check if device sent TRANSPORT_ERROR instead of ACK
        if(ackType == ControlByte.PacketType.TRANSPORT_ERROR) {
            int errorCode = ackPacket[5] & 0xFF;
            String errorName = getTransportErrorName(errorCode);
            throw new DeviceException("Transport error on channel 0x" + String.format("%04X", channelId) + ": " + errorName + " (code " + errorCode + ")");
        }

        if(ackType != ControlByte.PacketType.ACK) {
            throw new DeviceException("Expected ACK for sent message, got " + ackType +
                    " (control_byte=0x" + String.format("%02X", ackPacket[0] & 0xFF) + ")");
        }

        // Receive the response
        byte[] firstPacket = transport.read();
        if(firstPacket == null || firstPacket.length != 64) {
            throw new DeviceException("Invalid handshake response packet");
        }

        // Verify expected packet type
        ControlByte.PacketType packetType = ControlByte.getPacketType(firstPacket[0]);
        if(packetType == ControlByte.PacketType.TRANSPORT_ERROR) {
            // Read error code (first byte of payload, at offset 5)
            int errorCode = firstPacket[5] & 0xFF;
            String errorName = getTransportErrorName(errorCode);
            throw new DeviceException("Transport error during handshake on channel 0x" +
                    String.format("%04X", channelId) + ": " + errorName + " (code " + errorCode + ")");
        }
        if(packetType != expectedResponseType) {
            throw new DeviceException("Expected " + expectedResponseType + ", got " + packetType);
        }

        // Reassemble response
        java.util.List<byte[]> packets = new java.util.ArrayList<>();
        packets.add(firstPacket);

        int totalLength = PacketCodec.getLength(firstPacket);
        int requiredPackets = calculateRequiredPackets(totalLength);

        for(int i = 1; i < requiredPackets; i++) {
            byte[] packet = transport.read();
            if(packet == null || !ControlByte.isContinuation(packet[0])) {
                throw new DeviceException("Invalid continuation packet in handshake");
            }
            packets.add(packet);
        }

        PacketCodec.ReassembledMessage message = PacketCodec.reassemble(packets);

        // ABP: Send ACK for received message
        byte ackControlByte = ControlByte.createAck(ControlByte.getSequenceBit(firstPacket[0]));
        // ACK has empty payload, but still needs proper THP packet format with length and CRC
        byte[] emptyPayload = new byte[0];
        for(byte[] respAck : PacketCodec.segment(ackControlByte, channelId, emptyPayload)) {
            transport.write(respAck);
        }

        return message.applicationData;
    }

    /**
     * Get transport error name from error code.
     */
    private static String getTransportErrorName(int errorCode) {
        return switch(errorCode) {
            case 1 -> "TRANSPORT_BUSY";
            case 2 -> "UNALLOCATED_CHANNEL";
            case 3 -> "DECRYPTION_FAILED";
            case 5 -> "DEVICE_LOCKED";
            default -> "UNKNOWN";
        };
    }

    /**
     * Calculate number of packets required for a message.
     */
    private int calculateRequiredPackets(int transportPayloadLength) {
        // Length already includes CRC
        int firstPacketPayload = 59;
        if(transportPayloadLength <= firstPacketPayload) {
            return 1;
        }
        int remainingBytes = transportPayloadLength - firstPacketPayload;
        int continuationPacketPayload = 61;
        return 1 + (remainingBytes + continuationPacketPayload - 1) / continuationPacketPayload;
    }

    // ===== Callback Handlers =====

    private Message callbackPin(TrezorMessageCommon.PinMatrixRequest pinMatrixRequest) throws DeviceException {
        String pin;
        try {
            pin = ui.getPin(pinMatrixRequest.getType().getNumber());
        } catch(UserRefusedException e) {
            callRaw(TrezorMessageManagement.Cancel.newBuilder().build());
            throw e;
        }

        if(!pin.matches("\\d+") || pin.isEmpty() || pin.length() > MAX_PIN_LENGTH) {
            throw new DeviceException("Invalid PIN format");
        }

        return callRaw(TrezorMessageCommon.PinMatrixAck.newBuilder().setPin(pin).build());
    }

    @SuppressWarnings("deprecation")
    private Message callbackPassphrase(TrezorMessageCommon.PassphraseRequest passphraseRequest) throws DeviceException {
        boolean availableOnDevice = passphraseRequest.hasOnDevice() && passphraseRequest.getOnDevice();

        if(availableOnDevice && callbacks.isPassphraseEntryAvailable()) {
            return sendPassphrase(null, true);
        }

        Object passphrase;
        try {
            passphrase = ui.getPassphrase(availableOnDevice);
        } catch(UserRefusedException e) {
            callRaw(TrezorMessageManagement.Cancel.newBuilder().build());
            throw e;
        }

        if(TrezorDevice.PASSPHRASE_ON_DEVICE.equals(passphrase)) {
            if(!availableOnDevice) {
                callRaw(TrezorMessageManagement.Cancel.newBuilder().build());
                throw new DeviceException("Device is not capable of entering passphrase");
            } else {
                return sendPassphrase(null, Boolean.TRUE);
            }
        }

        if(passphrase instanceof String strPassphrase) {
            strPassphrase = Normalizer.normalize(strPassphrase, Normalizer.Form.NFKD);
            if(strPassphrase.length() > MAX_PASSPHRASE_LENGTH) {
                callRaw(TrezorMessageManagement.Cancel.newBuilder().build());
                throw new IllegalArgumentException("Passphrase exceeds maximum length");
            }

            return sendPassphrase(strPassphrase, Boolean.FALSE);
        } else {
            throw new IllegalArgumentException("Passphrase must be a String");
        }
    }

    @SuppressWarnings("deprecation")
    private Message sendPassphrase(String passphrase, Boolean onDevice) throws DeviceException {
        TrezorMessageCommon.PassphraseAck.Builder passphraseAck = TrezorMessageCommon.PassphraseAck.newBuilder();
        if(passphrase != null) {
            passphraseAck.setPassphrase(passphrase);
        }
        if(onDevice != null) {
            passphraseAck.setOnDevice(onDevice);
        }
        Message response = callRaw(passphraseAck.build());
        if(response instanceof TrezorMessageCommon.Deprecated_PassphraseStateRequest deprecatedPassphraseStateRequest) {
            byte[] sessionId = deprecatedPassphraseStateRequest.getState().toByteArray();
            callbacks.onSessionIdChanged(sessionId);
            response = callRaw(TrezorMessageCommon.Deprecated_PassphraseStateAck.newBuilder().build());
        }
        return response;
    }

    private Message callbackButton(TrezorMessageCommon.ButtonRequest buttonRequest) throws DeviceException {
        sendMessage(TrezorMessageCommon.ButtonAck.newBuilder().build());
        ui.buttonRequest(buttonRequest.getCode().getNumber());
        return receiveMessage();
    }

    // ===== Message I/O =====

    private void sendMessage(Message message) throws DeviceException {
        if(transport.isClosed()) {
            throw new IllegalStateException("sendMessage: transport already closed, cannot send message");
        }

        // Get message type
        String msgName = message.getClass().getSimpleName();
        if(msgName.startsWith("TxAck")) {
            msgName = "TxAck";
        }

        // Determine message type from appropriate enum
        int messageType;
        try {
            // Try regular MessageType enum first (includes most messages including ThpCreateNewSession)
            messageType = TrezorMessage.MessageType.valueOf("MessageType_" + msgName).getNumber();
        } catch(IllegalArgumentException e) {
            // Fall back to THP-specific MessageType enum for pairing messages
            messageType = TrezorMessageThp.ThpMessageType.valueOf("ThpMessageType_" + msgName).getNumber();
        }

        // Encode message: session_id (1 byte) + type (2 bytes BE) + protobuf payload
        byte[] protobufBytes = message.toByteArray();
        byte[] applicationData = new byte[3 + protobufBytes.length];
        applicationData[0] = 0;  // Session ID = 0 for pairing/initial session
        applicationData[1] = (byte)((messageType >> 8) & 0xFF);
        applicationData[2] = (byte)(messageType & 0xFF);
        System.arraycopy(protobufBytes, 0, applicationData, 3, protobufBytes.length);

        if(log.isDebugEnabled()) {
            log.debug("> {} (type={}, {} bytes): {}", msgName, messageType, protobufBytes.length,
                    Utils.bytesToHex(protobufBytes));
        }

        encryptedTransport.sendMessage(applicationData);
    }

    private Message receiveMessage() throws DeviceException {
        if(transport.isClosed()) {
            throw new IllegalStateException("receiveMessage: transport already closed, cannot receive message");
        }

        try {
            byte[] messageBytes = encryptedTransport.receiveMessage();

            if(log.isDebugEnabled()) {
                log.debug("< Message ({} bytes): {}", messageBytes.length, Utils.bytesToHex(messageBytes));
            }

            // Parse THP message: session_id (1 byte) + type (2 bytes BE) + protobuf payload
            if(messageBytes.length < 3) {
                throw new InvalidProtocolBufferException("Message too short");
            }

            int sessionId = messageBytes[0] & 0xFF;
            int msgId = (((int) messageBytes[1] & 0xFF) << 8) + ((int) messageBytes[2] & 0xFF);

            // Try to find message type in either enum
            TrezorMessage.MessageType messageType = TrezorMessage.MessageType.forNumber(msgId);
            TrezorMessageThp.ThpMessageType thpMessageType = null;

            String messageTypeName;
            if(messageType != null) {
                messageTypeName = messageType.name();
            } else {
                // Try THP message type
                thpMessageType = TrezorMessageThp.ThpMessageType.forNumber(msgId);
                if(thpMessageType == null) {
                    throw new InvalidProtocolBufferException("Unknown message type: " + msgId);
                }
                messageTypeName = thpMessageType.name();
            }

            if(log.isDebugEnabled()) {
                log.debug("< Session {} message type {} ({})", sessionId, msgId, messageTypeName);
            }

            // Extract payload (skip 3-byte header)
            byte[] payload = new byte[messageBytes.length - 3];
            System.arraycopy(messageBytes, 3, payload, 0, payload.length);

            // Parse protobuf message
            Method method = extractParserMethod(messageTypeName);
            Message message = (Message) method.invoke(null, payload);

            if(log.isDebugEnabled()) {
                String msgName = message.getClass().getSimpleName();
                log.debug("< {}", msgName);
            }

            return message;

        } catch(InvalidProtocolBufferException e) {
            throw new DeviceException("Error parsing message from Trezor", e);
        } catch(Exception e) {
            throw new DeviceException("Error receiving message from Trezor", e);
        }
    }

    private Method extractParserMethod(String messageTypeName) throws ClassNotFoundException, NoSuchMethodException {
        if(log.isTraceEnabled()) {
            log.trace("Parsing type {}", messageTypeName);
        }

        // Identify the expected inner class name
        String innerClassName = messageTypeName.replace("ThpMessageType_", "").replace("MessageType_", "");

        // Identify enclosing class by name
        String className;
        if(innerClassName.equals("ButtonAck")
                || innerClassName.equals("ButtonRequest")
                || innerClassName.equals("Failure")
                || innerClassName.equals("HDNodeType")
                || innerClassName.equals("PassphraseAck")
                || innerClassName.equals("PassphraseRequest")
                || innerClassName.equals("PassphraseStateAck")
                || innerClassName.equals("PassphraseStateRequest")
                || innerClassName.equals("PinMatrixAck")
                || innerClassName.equals("PinMatrixRequest")
                || innerClassName.equals("Success")
        ) {
            // Use common classes
            className = TrezorMessageCommon.class.getName() + "$" + innerClassName;
        } else if(innerClassName.equals("PublicKey")
                || innerClassName.equals("Address")
                || innerClassName.equals("TxRequest")
                || innerClassName.equals("TxAckMeta")
                || innerClassName.equals("TxAckInput")
                || innerClassName.equals("TxAckOutput")
                || innerClassName.equals("TxAckPrevMeta")
                || innerClassName.equals("TxAckPrevInput")
                || innerClassName.equals("TxAckPrevOuput")
                || innerClassName.equals("MessageSignature")
        ) {
            className = TrezorMessageBitcoin.class.getName() + "$" + innerClassName;
        } else if(innerClassName.startsWith("Thp")) {
            // THP messages (ThpPairingRequest, ThpCredentialResponse, etc.)
            className = TrezorMessageThp.class.getName() + "$" + innerClassName;
        } else {
            // Use management class as default
            className = TrezorMessageManagement.class.getName() + "$" + innerClassName;
        }

        if(log.isTraceEnabled()) {
            log.trace("Expected class name: {}", className);
        }

        Class<?> messageClass = Class.forName(className);
        return messageClass.getMethod("parseFrom", byte[].class);
    }

    // ===== Accessors =====

    /**
     * Get the current pairing state (only available after initialization).
     */
    public HandshakeMessages.PairingState getPairingState() {
        return pairingState;
    }

    /**
     * Get the host static key pair (for saving to storage).
     */
    public KeyPair getHostStaticKeyPair() {
        return hostStaticKeyPair;
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
