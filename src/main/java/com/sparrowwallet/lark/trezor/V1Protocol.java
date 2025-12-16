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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Arrays;

/**
 * Codec v1 protocol implementation (pre-2025 Trezor devices).
 *
 * Packet format: ?## + 2-byte message type + 4-byte length + protobuf data
 * No encryption, no channel management, direct USB I/O.
 */
class V1Protocol implements Protocol {
    private static final Logger log = LoggerFactory.getLogger(V1Protocol.class);

    private static final int REPLEN = 64;
    private static final int TIMEOUT = 2000; // ms
    private static final int MAX_PASSPHRASE_LENGTH = 50;
    private static final int MAX_PIN_LENGTH = 50;

    private final Transport transport;
    private final TrezorUI ui;
    private final ProtocolCallbacks callbacks;

    /**
     * Create V1 protocol instance.
     *
     * @param transport The underlying transport (USB, etc.)
     * @param ui User interaction callbacks
     * @param callbacks Protocol callbacks for device communication
     */
    V1Protocol(Transport transport, TrezorUI ui, ProtocolCallbacks callbacks) {
        this.transport = transport;
        this.ui = ui;
        this.callbacks = callbacks;
    }

    @Override
    public <T extends Message> T call(Message message, Class<T> toValueType) throws DeviceException {
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
            callRaw(TrezorMessageManagement.Cancel.newBuilder().build());
            throw new IllegalArgumentException("Invalid pin provided");
        }

        Message response = callRaw(TrezorMessageCommon.PinMatrixAck.newBuilder().setPin(pin).build());
        if(response instanceof TrezorMessageCommon.Failure failure && (failure.getCode() == TrezorMessageCommon.Failure.FailureType.Failure_PinInvalid ||
                failure.getCode() == TrezorMessageCommon.Failure.FailureType.Failure_PinCancelled ||
                failure.getCode() == TrezorMessageCommon.Failure.FailureType.Failure_PinExpected)) {
            throw new DeviceException(failure.getMessage());
        } else {
            return response;
        }
    }

    @SuppressWarnings("deprecation")
    private Message callbackPassphrase(TrezorMessageCommon.PassphraseRequest passphraseRequest) throws DeviceException {
        boolean availableOnDevice = callbacks.isPassphraseEntryAvailable();

        if(passphraseRequest.getOnDevice()) {
            return sendPassphrase(null, null);
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
        messageWrite(message);
    }

    private Message receiveMessage() throws DeviceException {
        if(transport.isClosed()) {
            throw new IllegalStateException("receiveMessage: transport already closed, cannot receive message");
        }

        try {
            return messageRead();
        } catch(InvalidProtocolBufferException e) {
            throw new DeviceException("Error reading from Trezor", e);
        }
    }

    // ===== v1 Wire Protocol =====

    private void messageWrite(Message message) throws DeviceException {
        // Message parameters
        int msgSize = message.getSerializedSize();
        String msgName = message.getClass().getSimpleName();
        if(log.isDebugEnabled()) {
            log.debug("> " + msgName);
        }
        if(msgName.startsWith("TxAck")) {
            msgName = "TxAck";
        }
        int messageType = TrezorMessage.MessageType.valueOf("MessageType_" + msgName).getNumber();
        byte[] messageBytes = message.toByteArray();
        if(log.isDebugEnabled()) {
            log.debug("Type " + messageType + " (" + messageBytes.length + " bytes):" + Utils.bytesToHex(messageBytes));
        }
        messageWrite(messageType, messageBytes);
    }

    private void messageWrite(int messageType, byte[] messageData) throws DeviceException {
        // Step 1: Create a header with ">HL" (big-endian short and int)
        ByteBuffer headerBuffer = ByteBuffer.allocate(6);
        headerBuffer.putShort((short) messageType);
        headerBuffer.putInt(messageData.length);

        // Step 2: Combine "##", header, and message data into a single ByteBuffer
        ByteBuffer buffer = ByteBuffer.allocate(2 + headerBuffer.capacity() + messageData.length);
        buffer.put("##".getBytes(StandardCharsets.UTF_8));
        buffer.put(headerBuffer.array());
        buffer.put(messageData);

        buffer.flip(); // Prepare buffer for reading

        // Step 3: Write buffer in chunks, prepending '?' and padding to 63 bytes
        byte[] tempBuffer = new byte[REPLEN];
        while(buffer.hasRemaining()) {
            int chunkSize = Math.min(buffer.remaining(), REPLEN - 1);

            // Set Report ID and copy data
            tempBuffer[0] = (byte) '?';
            buffer.get(tempBuffer, 1, chunkSize);

            // Pad remaining bytes with zeroes if needed
            for(int i = chunkSize + 1; i < REPLEN; i++) {
                tempBuffer[i] = 0;
            }

            // Send chunk
            transport.write(tempBuffer);
        }
    }

    private Message messageRead() throws InvalidProtocolBufferException, DeviceException {
        ByteBuffer messageBuffer;
        TrezorMessage.MessageType messageType;
        int invalidChunksCounter = 0;

        int msgId;
        int msgSize;

        // Start by attempting to read the first chunk
        // with the assumption that the read buffer initially
        // contains random data and needs to be synch'd up
        for(; ; ) {
            byte[] readBytes;
            try {
                readBytes = transport.read(TIMEOUT);
            } catch(DeviceTimeoutException e) {
                // Allow polling to timeout when there is no data
                // Continue retrying indefinitely for first chunk
                continue;
            }

            // Check for invalid header length
            if(readBytes.length < 9) {
                if(invalidChunksCounter++ > 5) {
                    if(log.isTraceEnabled()) {
                        log.trace("< Header{}", Utils.bytesToHex(readBytes));
                    }
                    throw new InvalidProtocolBufferException("Header too short after multiple chunks");
                }
                // Restart the loop
                continue;
            }

            // Check for invalid header sync pattern
            if(readBytes[0] != (byte) '?'
                    || readBytes[1] != (byte) '#'
                    || readBytes[2] != (byte) '#') {
                if(invalidChunksCounter++ > 5) {
                    if(log.isTraceEnabled()) {
                        log.trace("< Header{}", Utils.bytesToHex(readBytes));
                    }
                    throw new InvalidProtocolBufferException("Header invalid after multiple chunks");
                }
                // Restart the loop
                continue;
            }

            // Must be OK to be here
            if(log.isTraceEnabled()) {
                log.trace("< Header{}", Utils.bytesToHex(readBytes));
            }

            msgId = (((int) readBytes[3] & 0xFF) << 8) + ((int) readBytes[4] & 0xFF);
            msgSize = (((int) readBytes[5] & 0xFF) << 24)
                    + (((int) readBytes[6] & 0xFF) << 16)
                    + (((int) readBytes[7] & 0xFF) << 8)
                    + ((int) readBytes[8] & 0xFF);

            // Allocate the message payload buffer
            messageBuffer = ByteBuffer.allocate(msgSize + 1024);
            messageBuffer.put(readBytes, 9, readBytes.length - 9);
            messageType = TrezorMessage.MessageType.forNumber(msgId);
            break;
        }

        // Read in the remaining payload data
        invalidChunksCounter = 0;

        while(messageBuffer.position() < msgSize) {
            byte[] readBytes = transport.read(TIMEOUT);

            // Sanity check on the chunk
            if(readBytes[0] != (byte) '?') {
                // Unexpected value in the first position - should be 63
                if(invalidChunksCounter++ > 5) {
                    throw new InvalidProtocolBufferException("Chunk invalid in payload");
                }
                continue;
            }
            messageBuffer.put(readBytes, 1, readBytes.length - 1);
        }

        byte[] msgData = Arrays.copyOfRange(messageBuffer.array(), 0, msgSize);

        if(log.isTraceEnabled()) {
            log.trace("< Message{}", Utils.bytesToHex(msgData));
        }

        try {
            Method method = extractParserMethod(messageType);
            //noinspection PrimitiveArrayArgumentToVariableArgMethod
            Message message = (Message) method.invoke(null, msgData);
            if(log.isDebugEnabled()) {
                String msgName = message.getClass().getSimpleName();
                log.debug("< " + msgName);
            }
            if(log.isDebugEnabled()) {
                log.debug("Type " + messageType.getNumber() + " (" + msgData.length + " bytes):" + Utils.bytesToHex(msgData));
            }
            return message;
        } catch(Exception ex) {
            throw new InvalidProtocolBufferException("Exception while calling: parseMessageFromBytes for MessageType: " + messageType.name());
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
            // Use management class as default then check if inner class indicates another
            className = TrezorMessageManagement.class.getName() + "$" + innerClassName;
        }

        if(log.isTraceEnabled()) {
            log.trace("Expected class name: {}", className);
        }
        Class<?> cls = Class.forName(className);

        return cls.getDeclaredMethod("parseFrom", byte[].class);
    }
}
