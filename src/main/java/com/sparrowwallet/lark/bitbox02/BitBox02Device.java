package com.sparrowwallet.lark.bitbox02;

import com.google.protobuf.InvalidProtocolBufferException;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECDSASignature;
import com.sparrowwallet.drongo.crypto.Secp256r1Key;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.drongo.Version;
import com.sparrowwallet.lark.bitbox02.generated.Bitbox02System;
import com.sparrowwallet.lark.bitbox02.generated.Btc;
import com.sparrowwallet.lark.bitbox02.generated.Hww;
import com.sparrowwallet.lark.bitbox02.generated.Mnemonic;
import org.hid4java.HidDevice;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BitBox02Device implements Closeable {
    private static final Logger log = LoggerFactory.getLogger(BitBox02Device.class);

    public static final int BITBOX02_VID = 0x03eb;
    public static final int BITBOX02_PID = 0x2403;

    public static final int ERR_GENERIC = 103;
    public static final int ERR_DUPLICATE_ENTRY = 107;
    public static final int ERR_USER_ABORT = 104;

    private static final Pattern DEVICE_VERSION = Pattern.compile("v([0-9]+\\.[0-9]+\\.[0-9]+)");

    private static final Version MIN_UNSUPPORTED_BITBOX02_FIRMWARE_VERSION = new Version("10.0.0");

    private final Version version;

    private final BitBoxProtocol bitBoxProtocol;

    public BitBox02Device(HidDevice hidDevice, TransportLayer transportLayer, BitBoxNoiseConfig bitBoxNoiseConfig) throws DeviceException {
        String serialNumber = hidDevice.getSerialNumber();

        hidDevice.open();

        Matcher matcher = DEVICE_VERSION.matcher(serialNumber);
        if(matcher.find()) {
            this.version = new Version(matcher.group(1));
            if(version.compareTo(MIN_UNSUPPORTED_BITBOX02_FIRMWARE_VERSION) >= 0) {
                throw new DeviceException("The BitBox02's firmware version " + version + " is too new for this application.");
            }

            if(version.compareTo(new Version("7.0.0")) >= 0) {
                this.bitBoxProtocol = new BitBoxProtocolV7(transportLayer);
            } else if(version.compareTo(new Version("4.0.0")) >= 0) {
                this.bitBoxProtocol = new BitBoxProtocolV4(transportLayer);
            } else if(version.compareTo(new Version("3.0.0")) >= 0) {
                this.bitBoxProtocol = new BitBoxProtocolV3(transportLayer);
            } else if(version.compareTo(new Version("2.0.0")) >= 0) {
                this.bitBoxProtocol = new BitBoxProtocolV2(transportLayer);
            } else {
                this.bitBoxProtocol = new BitBoxProtocolV1(transportLayer);
            }

            try {
                if(version.compareTo(new Version("2.0.0")) >= 0) {
                    bitBoxNoiseConfig.attestationCheck(performAttestation());
                    bitBoxProtocol.unlockQuery();
                }

                bitBoxProtocol.noiseConnect(bitBoxNoiseConfig);

                DeviceInfo deviceInfo = getDeviceInfo();
                if(!deviceInfo.initialized()) {
                    throw new DeviceException("The BitBox02 must be initialized first");
                }

                if(deviceInfo.getVersion().compareTo(new Version("9.0.0")) < 0) {
                    throw new DeviceException("The BitBox02 firmware must be updated to at least version 9.0.0");
                }
            } catch(Exception e) {
                throw new DeviceException(e.getMessage(), e);
            }
        } else {
            throw new DeviceException("Could not parse version from " + serialNumber);
        }
    }

    private boolean performAttestation() throws DeviceException {
        SecureRandom secureRandom = new SecureRandom();
        byte[] challenge = new byte[32];
        secureRandom.nextBytes(challenge);

        BitBoxProtocol.Response response = bitBoxProtocol.query(BitBoxProtocol.OP_ATTESTATION, challenge);
        if(!Arrays.equals(response.status, BitBoxProtocol.RESPONSE_SUCCESS)) {
            return false;
        }

        byte[] bootloaderHash = Arrays.copyOfRange(response.data, 0, 32);
        byte[] devicePubkeyBytes = Arrays.copyOfRange(response.data, 32, 96);
        byte[] certificate = Arrays.copyOfRange(response.data, 96, 160);
        byte[] rootPubkeyIdentifier = Arrays.copyOfRange(response.data, 160, 192);
        byte[] challengeSignature = Arrays.copyOfRange(response.data, 192, 256);

        Map<Sha256Hash, AttestationKeys.AttestationPubkeyInfo> attestationPubkeyInfoMap = AttestationKeys.getPubKeysMap();
        if(!attestationPubkeyInfoMap.containsKey(Sha256Hash.wrap(rootPubkeyIdentifier))) {
            return false;
        }

        AttestationKeys.AttestationPubkeyInfo rootPubKeyInfo = attestationPubkeyInfoMap.get(Sha256Hash.wrap(rootPubkeyIdentifier));
        if(rootPubKeyInfo.getAcceptedBootloaderHash() != null && !Arrays.equals(rootPubKeyInfo.getAcceptedBootloaderHash(), bootloaderHash)) {
            return false;
        }

        int halfLength = certificate.length / 2;
        byte[] r = new byte[halfLength];
        byte[] s = new byte[halfLength];
        System.arraycopy(certificate, 0, r, 0, halfLength);
        System.arraycopy(certificate, halfLength, s, 0, halfLength);

        ECDSASignature signature = new ECDSASignature(new BigInteger(1, r), new BigInteger(1, s));
        if(!signature.verify(Sha256Hash.hash(Utils.concat(bootloaderHash, devicePubkeyBytes)), rootPubKeyInfo.getPubkey())) {
            return false;
        }

        Secp256r1Key secp256r1Key = new Secp256r1Key(Utils.concat(new byte[] { 0x04 }, devicePubkeyBytes));
        if(!secp256r1Key.verify(Sha256Hash.hash(challenge), challengeSignature)) {
            return false;
        }

        return true;
    }

    private DeviceInfo getDeviceInfo() throws DeviceException {
        Hww.Request.Builder request = Hww.Request.newBuilder();
        request.setDeviceInfo(Bitbox02System.DeviceInfoRequest.newBuilder().build());
        Hww.Response hwwResponse = msgQuery(request.build(), Hww.Response.ResponseCase.DEVICE_INFO);
        Bitbox02System.DeviceInfoResponse deviceInfoResponse = hwwResponse.getDeviceInfo();
        return new DeviceInfo(deviceInfoResponse.getName(), deviceInfoResponse.getVersion(), deviceInfoResponse.isInitialized(), deviceInfoResponse.getMnemonicPassphraseEnabled(),
                deviceInfoResponse.getMonotonicIncrementsRemaining(), deviceInfoResponse.getSecurechipModel());
    }

    public Hww.Response msgQuery(Hww.Request request, Hww.Response.ResponseCase expectedResponse) throws DeviceException {
        byte[] responseBytes = bitBoxProtocol.encryptedQuery(request.toByteArray());

        try {
            if(log.isDebugEnabled()) {
                log.debug(request.toString());
            }

            Hww.Response response = Hww.Response.parseFrom(responseBytes);
            if(response.hasError()) {
                if(response.getError().getCode() == ERR_USER_ABORT) {
                    throw new BitBox02Exception(response.getError().getMessage(), response.getError().getCode());
                }
                throw new BitBox02Exception(response.getError().getMessage(), response.getError().getCode());
            }
            if(expectedResponse != null && response.getResponseCase() != expectedResponse) {
                throw new DeviceException("Unexpected response: " + response.getResponseCase() + ", expected: " + expectedResponse);
            }

            if(log.isDebugEnabled()) {
                log.debug(response.toString());
            }

            return response;
        } catch(InvalidProtocolBufferException e) {
            throw new DeviceException("Invalid protocol buffer in response", e);
        }
    }

    public Btc.BTCResponse btcMsgQuery(Btc.BTCRequest request, Btc.BTCResponse.ResponseCase expectedResponse) throws DeviceException {
        Hww.Request requestBuilder = Hww.Request.newBuilder().setBtc(request).build();
        Btc.BTCResponse response = msgQuery(requestBuilder, Hww.Response.ResponseCase.BTC).getBtc();

        if(expectedResponse != null && response.getResponseCase() != expectedResponse) {
            throw new DeviceException("Unexpected response: " + response.getResponseCase() + ", expected: " + expectedResponse);
        }

        return response;
    }

    public void togglePassphrase() throws DeviceException {
        DeviceInfo deviceInfo = getDeviceInfo();
        Hww.Request requestBuilder = Hww.Request.newBuilder()
                .setSetMnemonicPassphraseEnabled(Mnemonic.SetMnemonicPassphraseEnabledRequest.newBuilder()
                        .setEnabled(!deviceInfo.mnemnoicPassphraseEnabled()).build()).build();
        msgQuery(requestBuilder, Hww.Response.ResponseCase.SUCCESS);
    }

    public void requireAtLeastVersion(Version version) throws DeviceException {
        if(this.version.compareTo(version) < 0) {
            throw new DeviceException("Update the BitBox02 firmware to at least version " + version);
        }
    }

    public Version getVersion() {
        return version;
    }

    @Override
    public void close() {
        bitBoxProtocol.close();
    }

    public record DeviceInfo(String name, String version, boolean initialized, boolean mnemnoicPassphraseEnabled, int monotonicIncrementsRemaining, String secureChipModel) {
        public Version getVersion() {
            return new Version(version.substring(1));
        }
    }
}
