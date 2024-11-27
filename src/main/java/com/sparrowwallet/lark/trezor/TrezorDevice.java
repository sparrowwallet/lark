package com.sparrowwallet.lark.trezor;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.ECDSASignature;
import com.sparrowwallet.drongo.crypto.SchnorrSignature;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.SigHash;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.UserRefusedException;
import com.sparrowwallet.drongo.Version;
import com.sparrowwallet.lark.trezor.generated.TrezorMessage;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageBitcoin;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageCommon;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageManagement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.usb4java.*;

import java.io.Closeable;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.*;
import java.util.stream.IntStream;

public class TrezorDevice implements Closeable {
    private static final Logger log = LoggerFactory.getLogger(TrezorDevice.class);

    private static final byte IN_ENDPOINT = (byte) 0x81;
    private static final byte OUT_ENDPOINT = (byte) 0x01;
    private static final int TIMEOUT = 400;
    private static final int TREZOR_INTERFACE = 0;
    private static final int REPLEN = 64;

    private static final int MAX_PASSPHRASE_LENGTH = 50;
    private static final int MAX_PIN_LENGTH = 50;

    public static final Object PASSPHRASE_ON_DEVICE = new Object();
    private static final String PASSPHRASE_TEST_PATH = "44h/1h/0h/0/0";

    private final DeviceHandle deviceHandle;
    private final TrezorUI trezorUI;

    private byte[] sessionId;
    private TrezorModel model;
    private Version version;
    private TrezorMessageManagement.Features features;

    public TrezorDevice(Device device, TrezorUI trezorUI) throws DeviceException {
        this.trezorUI = trezorUI;
        this.deviceHandle = new DeviceHandle();
        int result = LibUsb.open(device, deviceHandle);
        if(result != LibUsb.SUCCESS) {
            throw new DeviceException("Could not open Trezor at " + deviceHandle + ", returned " + result);
        }

        result = LibUsb.claimInterface(deviceHandle, TREZOR_INTERFACE);
        if(result != LibUsb.SUCCESS) {
            throw new DeviceException("Could not claim interface " + TREZOR_INTERFACE + " on Trezor at " + deviceHandle + ", returned " + result);
        }
    }

    public void initDevice() throws DeviceException {
        TrezorMessageManagement.Initialize initialize = TrezorMessageManagement.Initialize.newBuilder().build();
        Message response = callRaw(initialize);
        if(response instanceof TrezorMessageManagement.Features msgFeatures) {
            this.sessionId = msgFeatures.getSessionId().toByteArray();
            refreshFeatures(msgFeatures);
        } else if(response instanceof TrezorMessageCommon.Failure trezorFailure) {
            throw new DeviceException("Failure initializing device: " + trezorFailure.getMessage());
        } else {
            throw new DeviceException("Unexpected response initializing device: " + response);
        }
    }

    public TrezorMessageManagement.Features refreshFeatures() throws DeviceException {
        TrezorMessageManagement.GetFeatures getFeatures = TrezorMessageManagement.GetFeatures.newBuilder().build();
        Message response = callRaw(getFeatures);
        if(response instanceof TrezorMessageManagement.Features msgFeatures) {
            refreshFeatures(msgFeatures);
            return msgFeatures;
        } else {
            throw new DeviceException("Unexpected response to GetFeatures: " + response);
        }
    }

    private void refreshFeatures(TrezorMessageManagement.Features features) throws DeviceException {
        if(this.model == null) {
            this.model = TrezorModel.fromName(features.getModel());
            if(model == null) {
                throw new DeviceException("Unsupported Trezor model " + features.getModel());
            }
        }

        this.features = features;
        this.version = new Version(features.getMajorVersion() + "." + features.getMinorVersion() + "." + features.getPatchVersion());
        checkFirmwareVersion(true);
        if(features.hasSessionId()) {
            this.sessionId = features.getSessionId().toByteArray();
        }
    }

    private void checkFirmwareVersion(boolean warnOnly) throws DeviceException {
        if(isOutdated()) {
            if(warnOnly) {
                log.warn("Trezor firmware is outdated, please update to the latest version");
            } else {
                throw new DeviceException("Trezor firmware is outdated, please update to the latest version");
            }
        }
    }

    private boolean isOutdated() {
        if(features.getBootloaderMode()) {
            return false;
        }

        return version.compareTo(model.getMinimumVersion()) < 0;
    }

    public TrezorModel getModel() {
        return model;
    }

    public TrezorMessageManagement.Features getFeatures() {
        return features;
    }

    public TrezorUI getUI() {
        return trezorUI;
    }

    public void ensureUnlocked() throws DeviceException {
        getAddress(Network.TESTNET, PASSPHRASE_TEST_PATH, false, null, TrezorMessageBitcoin.InputScriptType.SPENDADDRESS, false);
        refreshFeatures();
    }

    public TrezorMessageBitcoin.PublicKey getPublicNode(Network network, List<ChildNumber> path) throws DeviceException {
        return getPublicNode(network, path, null, false, TrezorMessageBitcoin.InputScriptType.SPENDADDRESS, false);
    }

    public TrezorMessageBitcoin.PublicKey getPublicNode(Network network, List<ChildNumber> path, String ecdsaCurveName, boolean showDisplay,
                                                        TrezorMessageBitcoin.InputScriptType scriptType, boolean ignoreXpubMagic) throws DeviceException {
        TrezorMessageBitcoin.GetPublicKey.Builder getPublicKey = TrezorMessageBitcoin.GetPublicKey.newBuilder()
                .addAllAddressN(path.stream().map(ChildNumber::i).toList())
                .setCoinName(getCoinName(network))
                .setShowDisplay(showDisplay)
                .setIgnoreXpubMagic(ignoreXpubMagic);
        if(ecdsaCurveName != null) {
            getPublicKey.setEcdsaCurveName(ecdsaCurveName);
        }
        if(scriptType != null) {
            getPublicKey.setScriptType(scriptType);
        }
        return call(getPublicKey.build(), TrezorMessageBitcoin.PublicKey.class);
    }

    public String getAddress(Network network, String path, boolean showDisplay, TrezorMessageBitcoin.MultisigRedeemScriptType multisig,
                              TrezorMessageBitcoin.InputScriptType scriptType, boolean ignoreXpubMagic) throws DeviceException {
        TrezorMessageBitcoin.GetAddress.Builder getAddress = TrezorMessageBitcoin.GetAddress.newBuilder()
                .addAllAddressN(KeyDerivation.parsePath(path).stream().map(ChildNumber::i).toList())
                .setCoinName(getCoinName(network))
                .setShowDisplay(showDisplay)
                .setIgnoreXpubMagic(ignoreXpubMagic);
        if(multisig != null) {
            getAddress.setMultisig(multisig);
        }
        if(scriptType != null) {
            getAddress.setScriptType(scriptType);
        }
        return call(getAddress.build(), TrezorMessageBitcoin.Address.class).getAddress();
    }

    /**
     * Sign a Bitcoin-like transaction.
     *
     * Returns a list of signatures (one for each provided input) and the
     * network-serialized transaction.
     *
     * In addition to the required arguments, it is possible to specify additional
     * transaction properties (version, lock time, expiry...). Each additional argument
     * must correspond to a field in the `SignTx` data type. Note that some fields
     * (`inputs_count`, `outputs_count`, `coin_name`) will be inferred from the arguments.
     */
    public List<TransactionSignature> signTx(Network network, List<TrezorMessageBitcoin.TxInput> inputs, List<TrezorMessageBitcoin.TxOutput> outputs,
                       Map<Sha256Hash, PrevTx> prevTxs, long version, long locktime) throws DeviceException {

        if(prevTxs == null) {
            prevTxs = new HashMap<>();
        }

        TrezorMessageBitcoin.SignTx.Builder signTx = TrezorMessageBitcoin.SignTx.newBuilder()
                .setCoinName(getCoinName(network))
                .setInputsCount(inputs.size())
                .setOutputsCount(outputs.size())
                .setVersion((int)version)
                .setLockTime((int)locktime);

        List<TransactionSignature> signatures = new ArrayList<>();
        IntStream.range(0, inputs.size()).forEach(i -> signatures.add(null));
        byte[] serializedTx = new byte[0];

        Message response = call(signTx.build(), Message.class);
        while(true) {
            if(response instanceof TrezorMessageBitcoin.TxRequest txRequest) {
                serializedTx = extractStreamedData(serializedTx, signatures, txRequest.getSerialized());
                if(txRequest.getRequestType() == TrezorMessageBitcoin.TxRequest.RequestType.TXFINISHED) {
                    break;
                }

                TrezorMessageBitcoin.TxRequest.TxRequestDetailsType details = txRequest.getDetails();
                if(details.hasTxHash()) {
                    response = sendResponsePrev(prevTxs, txRequest.getRequestType(), details);
                } else {
                    response = sendResponseCurrent(inputs, outputs, txRequest.getRequestType(), details);
                }
            }
        }

        return signatures;
    }

    private byte[] extractStreamedData(byte[] serializedTx, List<TransactionSignature> signatures, TrezorMessageBitcoin.TxRequest.TxRequestSerializedType serialized) {
        if(serialized.hasSignatureIndex()) {
            TransactionSignature transactionSignature;
            byte[] signatureBytes = serialized.getSignature().toByteArray();
            if(signatureBytes.length == 64) {
                transactionSignature = new TransactionSignature(SchnorrSignature.decode(signatureBytes), SigHash.DEFAULT);
            } else {
                transactionSignature = new TransactionSignature(ECDSASignature.decodeFromDER(signatureBytes), SigHash.ALL);
            }
            signatures.set(serialized.getSignatureIndex(), transactionSignature);
        }

        return Utils.concat(serializedTx, serialized.getSerializedTx().toByteArray());
    }

    private Message sendResponsePrev(Map<Sha256Hash, PrevTx> prevTxs, TrezorMessageBitcoin.TxRequest.RequestType requestType,
                                     TrezorMessageBitcoin.TxRequest.TxRequestDetailsType details) throws DeviceException {
        PrevTx prevTx = prevTxs.get(Sha256Hash.wrap(details.getTxHash().toByteArray()));
        if(requestType == TrezorMessageBitcoin.TxRequest.RequestType.TXINPUT) {
            TrezorMessageBitcoin.PrevInput prevInput = prevTx.prevInputs().get(details.getRequestIndex());
            TrezorMessageBitcoin.TxAckPrevInput txAckPrevInput = TrezorMessageBitcoin.TxAckPrevInput.newBuilder()
                    .setTx(TrezorMessageBitcoin.TxAckPrevInput.TxAckPrevInputWrapper.newBuilder()
                            .setInput(prevInput).build()).build();
            return call(txAckPrevInput, Message.class);
        } else if(requestType == TrezorMessageBitcoin.TxRequest.RequestType.TXOUTPUT) {
            TrezorMessageBitcoin.PrevOutput prevOutput = prevTx.prevOutputs().get(details.getRequestIndex());
            TrezorMessageBitcoin.TxAckPrevOutput txAckPrevOutput = TrezorMessageBitcoin.TxAckPrevOutput.newBuilder()
                    .setTx(TrezorMessageBitcoin.TxAckPrevOutput.TxAckPrevOutputWrapper.newBuilder()
                            .setOutput(prevOutput).build()).build();
            return call(txAckPrevOutput, Message.class);
        } else if(requestType == TrezorMessageBitcoin.TxRequest.RequestType.TXMETA) {
            TrezorMessageBitcoin.TxAckPrevMeta txAckPrevMeta = TrezorMessageBitcoin.TxAckPrevMeta.newBuilder()
                    .setTx(prevTx.prevTx()).build();
            return call(txAckPrevMeta, Message.class);
        } else if(requestType == TrezorMessageBitcoin.TxRequest.RequestType.TXEXTRADATA) {
            throw new DeviceException("Tx extra data is not supported");
        } else {
            throw new DeviceException("Unexpected request " + requestType);
        }
    }

    private Message sendResponseCurrent(List<TrezorMessageBitcoin.TxInput> inputs, List<TrezorMessageBitcoin.TxOutput> outputs,
                                     TrezorMessageBitcoin.TxRequest.RequestType requestType,
                                     TrezorMessageBitcoin.TxRequest.TxRequestDetailsType details) throws DeviceException {
        if(requestType == TrezorMessageBitcoin.TxRequest.RequestType.TXINPUT) {
            TrezorMessageBitcoin.TxInput txInput = inputs.get(details.getRequestIndex());
            TrezorMessageBitcoin.TxAckInput txAckInput = TrezorMessageBitcoin.TxAckInput.newBuilder()
                    .setTx(TrezorMessageBitcoin.TxAckInput.TxAckInputWrapper.newBuilder()
                            .setInput(txInput).build()).build();
            return call(txAckInput, Message.class);
        } else if(requestType == TrezorMessageBitcoin.TxRequest.RequestType.TXOUTPUT) {
            TrezorMessageBitcoin.TxOutput txOutput = outputs.get(details.getRequestIndex());
            TrezorMessageBitcoin.TxAckOutput txAckOutput = TrezorMessageBitcoin.TxAckOutput.newBuilder()
                    .setTx(TrezorMessageBitcoin.TxAckOutput.TxAckOutputWrapper.newBuilder()
                            .setOutput(txOutput).build()).build();
            return call(txAckOutput, Message.class);
        } else {
            throw new DeviceException("Unexpected request " + requestType);
        }
    }

    public String signMessage(Network network, String path, String message, TrezorMessageBitcoin.InputScriptType scriptType) throws DeviceException {
        TrezorMessageBitcoin.SignMessage signMessage = TrezorMessageBitcoin.SignMessage.newBuilder()
                .setCoinName(getCoinName(network))
                .addAllAddressN(KeyDerivation.parsePath(path).stream().map(ChildNumber::i).toList())
                .setMessage(ByteString.copyFrom(Normalizer.normalize(message, Normalizer.Form.NFC), StandardCharsets.UTF_8))
                .setScriptType(scriptType).build();

        TrezorMessageBitcoin.MessageSignature response = call(signMessage, TrezorMessageBitcoin.MessageSignature.class);
        return Base64.getEncoder().encodeToString(response.getSignature().toByteArray());
    }

    public Message applySettings(String label, Boolean usePassphrase, byte[] homeScreen, Boolean passphraseAlwaysOnDevice, Integer autoLockDelayMs,
                              Integer displayRotation, TrezorMessageManagement.SafetyCheckLevel safetyCheckLevel, Boolean experimentalFeatures) throws DeviceException {
        TrezorMessageManagement.ApplySettings.Builder applySettings = TrezorMessageManagement.ApplySettings.newBuilder();
        if(label != null) {
            applySettings.setLabel(label);
        }
        if(usePassphrase != null) {
            applySettings.setUsePassphrase(usePassphrase);
        }
        if(homeScreen != null) {
            applySettings.setHomescreen(ByteString.copyFrom(homeScreen));
        }
        if(passphraseAlwaysOnDevice != null) {
            applySettings.setPassphraseAlwaysOnDevice(passphraseAlwaysOnDevice);
        }
        if(autoLockDelayMs != null) {
            applySettings.setAutoLockDelayMs(autoLockDelayMs);
        }
        if(displayRotation != null) {
            applySettings.setDisplayRotation(displayRotation);
        }
        if(safetyCheckLevel != null) {
            applySettings.setSafetyChecks(safetyCheckLevel);
        }
        if(experimentalFeatures != null) {
            applySettings.setExperimentalFeatures(experimentalFeatures);
        }

        Message resp = call(applySettings.build(), Message.class);
        refreshFeatures();
        return resp;
    }

    public boolean supportsExternal() {
        if(model.equals(TrezorModel.T1B1) && version.compareTo(new Version("1.10.5")) <= 0) {
            return true;
        }
        if(model.equals(TrezorModel.T2T1) && version.compareTo(new Version("2.4.3")) <= 0) {
            return true;
        }
        if(model.equals(TrezorModel.KEEPKEY)) {
            return true;
        }
        return false;
    }

    public boolean canSignTaproot() {
        if(model.equals(TrezorModel.T1B1)) {
            return version.compareTo(new Version("1.10.4")) >= 0;
        }
        if(model.equals(TrezorModel.T2T1)) {
            return version.compareTo(new Version("2.4.3")) >= 0;
        }
        if(model.equals(TrezorModel.KEEPKEY)) {
            return false;
        }
        return true;
    }

    public String getCoinName(Network network) {
        return network == Network.MAINNET ? "Bitcoin" : "Testnet";
    }

    public <T> T call(Message message, Class<T> toValueType) throws DeviceException {
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

    private Message callbackPin(TrezorMessageCommon.PinMatrixRequest pinMatrixRequest) throws DeviceException {
        String pin;
        try {
            pin = getUI().getPin(pinMatrixRequest.getType().getNumber());
        } catch(UserRefusedException e) {
            callRaw(TrezorMessageManagement.Cancel.newBuilder().build());
            throw e;
        }

        if(!pin.matches("\\d+") || pin.isEmpty() || pin.length() > MAX_PASSPHRASE_LENGTH) {
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
        boolean availableOnDevice = features.getCapabilitiesList().contains(TrezorMessageManagement.Features.Capability.Capability_PassphraseEntry);

        if(passphraseRequest.getOnDevice()) {
            return sendPassphrase(null, null);
        }

        Object passphrase;
        try {
            passphrase = getUI().getPassphrase(availableOnDevice);
        } catch(UserRefusedException e) {
            callRaw(TrezorMessageManagement.Cancel.newBuilder().build());
            throw e;
        }

        if(PASSPHRASE_ON_DEVICE.equals(passphrase)) {
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
            this.sessionId = deprecatedPassphraseStateRequest.getState().toByteArray();
            response = callRaw(TrezorMessageCommon.Deprecated_PassphraseStateAck.newBuilder().build());
        }
        return response;
    }

    private Message callbackButton(TrezorMessageCommon.ButtonRequest buttonRequest) throws DeviceException {
        sendMessage(TrezorMessageCommon.ButtonAck.newBuilder().build());
        getUI().buttonRequest(buttonRequest.getCode().getNumber());
        return receiveMessage();
    }

    public Message callRaw(Message message) throws DeviceException {
        sendMessage(message);
        return receiveMessage();
    }

    /**
     * Send a message to the device. The response will be contained in an asynchronous read
     * operation and delivered via the TrezorEvents mechanism.
     *
     * @param message The protobuf message to send.
     */
    private void sendMessage(Message message) throws DeviceException {
        if(deviceHandle == null) {
            throw new IllegalStateException("sendMessage: usbConnection already closed, cannot send message");
        }

        // Write the message
        messageWrite(message);
    }

    /**
     * Check the device data buffer using a blocking approach. It is expected that the upstream
     * caller will handle event distribution.
     *
     * @return The protobuf message that was read or null if nothing is present/timeout.
     */
    private Message receiveMessage() throws DeviceException {
        if(deviceHandle == null) {
            throw new IllegalStateException("receiveMessage: usbConnection already closed, cannot receive message");
        }

        try {
            return messageRead();
        } catch(InvalidProtocolBufferException e) {
            throw new DeviceException("Error reading from Trezor", e);
        }
    }

    /**
     * Release the interface and close this device.
     */
    public void close() {
        if(deviceHandle != null && deviceHandle.getPointer() != 0) {
            int result = LibUsb.releaseInterface(deviceHandle, TREZOR_INTERFACE);
            if(result != LibUsb.SUCCESS) {
                log.error("Unable to release interface, returned " + result);
            }

            LibUsb.close(deviceHandle);
        }
    }

    /**
     * Write a message to the Trezor including a suitable header inferred from the protobuf structure.
     *
     * @param message The protobuf message to write to the USB device.
     */
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
        messageWrite(messageType, message.toByteArray());
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
            writeChunk(tempBuffer);
        }
    }

    private void writeChunk(byte[] chunkBytes) throws DeviceException {
        ByteBuffer chunkBuffer = BufferUtils.allocateByteBuffer(64);
        chunkBuffer.put(chunkBytes);
        IntBuffer transferred = BufferUtils.allocateIntBuffer();

        // Send to device
        int result = LibUsb.bulkTransfer(
                deviceHandle,
                OUT_ENDPOINT,
                chunkBuffer,
                transferred,
                TIMEOUT
        );
        // Error checking
        if(result != LibUsb.SUCCESS) {
            if(result == LibUsb.ERROR_TIMEOUT) {
                throw new DeviceException("Timed out sending data");
            }

            throw new DeviceException("Unable to send data: " + result);
        }
    }

    /**
     * Read a message from the device.
     *
     * @return A protobuf message from the device.
     * @throws InvalidProtocolBufferException If something goes wrong.
     */
    @SuppressWarnings("unchecked")
    private Message messageRead() throws InvalidProtocolBufferException {
        ByteBuffer messageBuffer;
        TrezorMessage.MessageType messageType;
        int invalidChunksCounter = 0;

        int msgId;
        int msgSize;

        // Start by attempting to read the first chunk
        // with the assumption that the read buffer initially
        // contains random data and needs to be synch'd up
        for(; ; ) {
            ByteBuffer chunkBuffer = BufferUtils
                    .allocateByteBuffer(64)
                    .order(ByteOrder.LITTLE_ENDIAN);
            IntBuffer transferred = BufferUtils.allocateIntBuffer();

            int result = LibUsb.bulkTransfer(
                    deviceHandle,
                    IN_ENDPOINT,
                    chunkBuffer,
                    transferred,
                    TIMEOUT
            );
            // Allow polling to timeout when there is no data
            if(result == LibUsb.ERROR_TIMEOUT) {
                continue;
            }
            if(result != LibUsb.SUCCESS) {
                throw new LibUsbException("Unable to read data", result);
            }

            // Extract the chunk
            byte[] readBytes = new byte[chunkBuffer.remaining()];
            chunkBuffer.get(readBytes);

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
            ByteBuffer chunkBuffer = BufferUtils
                    .allocateByteBuffer(64)
                    .order(ByteOrder.LITTLE_ENDIAN);
            IntBuffer transferred = BufferUtils.allocateIntBuffer();

            int result = LibUsb.bulkTransfer(
                    deviceHandle,
                    IN_ENDPOINT,
                    chunkBuffer,
                    transferred,
                    TIMEOUT
            );
            if(result != LibUsb.SUCCESS) {
                throw new LibUsbException("Unable to read data", result);
            }

            // Extract the chunk
            byte[] readBytes = new byte[chunkBuffer.remaining()];
            chunkBuffer.get(readBytes);

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
            return message;
        } catch(Exception ex) {
            throw new InvalidProtocolBufferException("Exception while calling: parseMessageFromBytes for MessageType: " + messageType.name());
        }
    }

    /**
     * Identify a suitable parsing method from the message type name.
     *
     * @param messageType The abstract message type identifying the inner class and group.
     * @return A parsing method than can be invoked to convert the bytes into a message.
     * @throws ClassNotFoundException If the class could not be found (unknown message prefix).
     * @throws NoSuchMethodException  If the class was not a correctly formed protobuf message.
     */
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

    public record PrevTx(TrezorMessageBitcoin.PrevTx prevTx, List<TrezorMessageBitcoin.PrevInput> prevInputs, List<TrezorMessageBitcoin.PrevOutput> prevOutputs) {}
}
