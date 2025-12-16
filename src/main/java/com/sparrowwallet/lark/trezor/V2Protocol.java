package com.sparrowwallet.lark.trezor;

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.UserRefusedException;
import com.sparrowwallet.lark.trezor.generated.TrezorMessage;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageBitcoin;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageCommon;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageManagement;
import com.sparrowwallet.lark.trezor.thp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;
import java.security.KeyPair;
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

        // Step 3: Perform handshake (will get Trezor's static pubkey during handshake)
        // Note: We perform handshake without credential first
        // TODO: Implement credential lookup and re-handshake if we have existing pairing
        HandshakeStateMachine.Result handshakeResult = performHandshake(
                allocationResponse.channelId,
                allocationResponse.devicePropertiesBytes,
                null // credential - pairing phase not yet implemented
        );

        // Step 4: Extract Trezor's static public key from handshake result
        this.trezorStaticPubkey = handshakeResult.trezorStaticPubkey;

        // Step 5: Create encrypted transport
        this.encryptedTransport = new EncryptedTransport(
                transport,
                handshakeResult.transport,
                handshakeResult.channelId
        );
        this.pairingState = handshakeResult.pairingState;

        // Step 6: Save host static key
        saveHostStaticKey();

        // Step 7: Handle pairing state
        if(pairingState == HandshakeMessages.PairingState.UNPAIRED) {
            // TODO: Implement pairing flow to obtain credential
            if(log.isDebugEnabled()) {
                log.debug("Device is UNPAIRED - pairing flow not yet implemented");
            }
        } else {
            // Device is paired, credential exchange happens during pairing phase
            if(log.isDebugEnabled()) {
                log.debug("Device pairing state: {}", pairingState);
            }
        }

        if(log.isDebugEnabled()) {
            log.debug("THP session initialized (pairing state: {})", pairingState);
        }

        this.initialized = true;
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

                // Derive public key from private key
                java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("X25519");
                // Note: We can't easily derive public from private in standard Java
                // We'll need to store and load the public key as well, or regenerate
                // For now, just generate a new key pair
                return keyGen.generateKeyPair();
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
        int messageType = TrezorMessage.MessageType.valueOf("MessageType_" + msgName).getNumber();

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
            TrezorMessage.MessageType messageType = TrezorMessage.MessageType.forNumber(msgId);

            if(messageType == null) {
                throw new InvalidProtocolBufferException("Unknown message type: " + msgId);
            }

            if(log.isDebugEnabled()) {
                log.debug("< Session {} message type {}", sessionId, msgId);
            }

            // Extract payload (skip 3-byte header)
            byte[] payload = new byte[messageBytes.length - 3];
            System.arraycopy(messageBytes, 3, payload, 0, payload.length);

            // Parse protobuf message
            Method method = extractParserMethod(messageType);
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

    private Method extractParserMethod(TrezorMessage.MessageType messageType) throws ClassNotFoundException, NoSuchMethodException {
        if(log.isTraceEnabled()) {
            log.trace("Parsing type {}", messageType);
        }

        // Identify the expected inner class name
        String innerClassName = messageType.name().replace("MessageType_", "");

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
}
