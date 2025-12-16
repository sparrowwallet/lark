package com.sparrowwallet.lark.trezor;

import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.Version;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.ECDSASignature;
import com.sparrowwallet.drongo.crypto.SchnorrSignature;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.SigHash;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageBitcoin;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageCommon;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageManagement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.usb4java.Device;

import java.io.Closeable;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.*;
import java.util.stream.IntStream;

public class TrezorDevice implements Closeable, ProtocolCallbacks {
    private static final Logger log = LoggerFactory.getLogger(TrezorDevice.class);

    public static final Object PASSPHRASE_ON_DEVICE = new Object();
    private static final String PASSPHRASE_TEST_PATH = "44h/1h/0h/0/0";

    private final Protocol protocol;
    private final TrezorUI trezorUI;

    private byte[] sessionId;
    private TrezorModel model;
    private Version version;
    private TrezorMessageManagement.Features features;
    private boolean outdatedFirmware;

    /**
     * Create TrezorDevice with V1 protocol (public constructor for backward compatibility).
     *
     * @param device LibUsb device from enumeration
     * @param trezorUI User interaction callbacks
     * @param trezorModel The Trezor model (may be null, will be detected from features)
     * @throws DeviceException if device cannot be opened
     */
    public TrezorDevice(Device device, TrezorUI trezorUI, TrezorModel trezorModel) throws DeviceException {
        this.trezorUI = trezorUI;
        this.model = trezorModel;

        // Create USB transport
        UsbTransport transport = new UsbTransport(device);

        // Create V1 protocol
        this.protocol = new V1Protocol(transport, trezorUI, this);
    }

    /**
     * Create TrezorDevice with specified protocol.
     * Package-private constructor for factory use.
     *
     * @param protocol The protocol implementation (V1Protocol or V2Protocol)
     * @param trezorUI User interaction callbacks
     * @param trezorModel The Trezor model (may be null, will be detected from features)
     */
    TrezorDevice(Protocol protocol, TrezorUI trezorUI, TrezorModel trezorModel) {
        this.protocol = protocol;
        this.trezorUI = trezorUI;
        this.model = trezorModel;
    }

    public void initDevice() throws DeviceException {
        TrezorMessageManagement.Initialize initialize = TrezorMessageManagement.Initialize.newBuilder().build();
        Message response = protocol.callRaw(initialize);
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
        Message response = protocol.callRaw(getFeatures);
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
                this.model = TrezorModel.fromInternalName(features.getInternalModel());
            }
            if(model == null) {
                throw new IllegalStateException("Unsupported Trezor model: " + features.getModel() + " " + features.getInternalModel());
            }
            if(features.getLabel().startsWith("OneKey")) {
                if(model == TrezorModel.T1B1) {
                    model = TrezorModel.ONEKEY_CLASSIC_1S;
                } else if(model == TrezorModel.T2T1) {
                    model = TrezorModel.ONEKEY_PRO;
                }
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
            this.outdatedFirmware = true;
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

    public boolean isOutdatedFirmware() {
        return outdatedFirmware;
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
                              TrezorMessageManagement.DisplayRotation displayRotation, TrezorMessageManagement.SafetyCheckLevel safetyCheckLevel, Boolean experimentalFeatures) throws DeviceException {
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

    public <T extends Message> T call(Message message, Class<T> toValueType) throws DeviceException {
        return protocol.call(message, toValueType);
    }

    public Message callRaw(Message request) throws DeviceException {
        return protocol.callRaw(request);
    }

    // ===== ProtocolCallbacks Implementation =====

    @Override
    public boolean isPassphraseEntryAvailable() {
        if(features == null) {
            return false;
        }

        return features.getCapabilitiesList().contains(TrezorMessageManagement.Features.Capability.Capability_PassphraseEntry);
    }

    @Override
    public void onSessionIdChanged(byte[] sessionId) {
        this.sessionId = sessionId;
    }

    // ===== Cleanup =====

    /**
     * Release the interface and close this device.
     */
    public void close() {
        protocol.close();
    }

    public record PrevTx(TrezorMessageBitcoin.PrevTx prevTx, List<TrezorMessageBitcoin.PrevInput> prevInputs, List<TrezorMessageBitcoin.PrevOutput> prevOutputs) {}
}
