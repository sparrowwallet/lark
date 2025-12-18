package com.sparrowwallet.lark.bitbox02;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.X25519Key;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.UserRefusedException;
import com.sparrowwallet.lark.noise.NamedProtocolHandshakeBuilder;
import com.sparrowwallet.lark.noise.NoSuchPatternException;
import com.sparrowwallet.lark.noise.NoiseHandshake;
import com.sparrowwallet.lark.noise.NoiseTransport;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Optional;

public abstract class BitBoxProtocol {
    protected static final int HWW_CMD = 0x80 + 0x40 + 0x01;

    protected static final byte[] OP_ATTESTATION = new byte[] { (byte)'a' };
    protected static final byte[] OP_UNLOCK = new byte[] { (byte)'u' };
    protected static final byte[] OP_I_CAN_HAS_HANDSHAEK = new byte[] { (byte)'h' };
    protected static final byte[] OP_HER_COMEZ_TEH_HANDSHAEK = new byte[] { (byte)'H' };
    protected static final byte[] OP_I_CAN_HAS_PAIRIN_VERIFICASHUN = new byte[] { (byte)'v' };
    protected static final byte[] OP_NOISE_MSG = new byte[] { (byte)'n' };

    protected static final byte[] RESPONSE_SUCCESS = new byte[] { 0 };
    protected static final byte[] RESPONSE_FAILURE = new byte[] { 1 };

    protected final TransportLayer transportLayer;
    protected NoiseTransport noiseTransport;

    public BitBoxProtocol(TransportLayer transportLayer) {
        this.transportLayer = transportLayer;
    }

    public void close() {
        transportLayer.close();
    }

    public byte[] rawQuery(byte[] msg) throws DeviceException {
        long cid = transportLayer.generateCid();
        return transportLayer.query(msg, HWW_CMD, cid);
    }

    public Response query(byte[] cmd, byte[] msgData) throws DeviceException {
        byte[] response = rawQuery(Utils.concat(cmd, msgData));
        return new Response(Arrays.copyOfRange(response, 0, 1), Arrays.copyOfRange(response, 1, response.length));
    }

    public abstract byte[] encodeNoiseRequest(byte[] encryptedMsg);

    public abstract Response decodeNoiseResponse(byte[] encryptedMsg);

    public abstract Response handshakeQuery(byte[] req) throws DeviceException;

    public byte[] encryptedQuery(byte[] msg) throws DeviceException {
        byte[] encryptedMsg = noiseTransport.writeMessage(msg);
        encryptedMsg = encodeNoiseRequest(encryptedMsg);

        byte[] rawResponse = rawQuery(encryptedMsg);
        Response response = decodeNoiseResponse(rawResponse);
        if(!Arrays.equals(response.status, BitBoxProtocol.RESPONSE_SUCCESS)) {
            throw new DeviceException("Noise communication failed.");
        }

        try {
            return noiseTransport.readMessage(response.data);
        } catch(AEADBadTagException e) {
            throw new DeviceException("Unable to verify authentication tag", e);
        }
    }

    public NoiseTransport createNoiseChannel(BitBoxNoiseConfig bitBoxNoiseConfig) throws DeviceException {
        if(!Arrays.equals(rawQuery(OP_I_CAN_HAS_HANDSHAEK), RESPONSE_SUCCESS)) {
            throw new DeviceException("Couldn't kick off handshake");
        }

        // init noise channel
        try {
            X25519Key appStaticKey;
            Optional<X25519Key> optAppStaticKey = bitBoxNoiseConfig.getAppStaticKey();
            if(optAppStaticKey.isEmpty()) {
                appStaticKey = new X25519Key();
                bitBoxNoiseConfig.setAppStaticKey(appStaticKey);
            } else {
                appStaticKey = optAppStaticKey.get();
            }

            final NoiseHandshake initiatorHandshake = new NamedProtocolHandshakeBuilder("Noise_XX_25519_ChaChaPoly_SHA256", NoiseHandshake.Role.INITIATOR)
                    .setLocalStaticKeyPair(appStaticKey.getKeyPair())
                    .setPrologue("Noise_XX_25519_ChaChaPoly_SHA256".getBytes(StandardCharsets.UTF_8))
                    .build();

            Response startHandshakeReply = handshakeQuery(initiatorHandshake.writeMessage((byte[]) null));
            if(!Arrays.equals(startHandshakeReply.status, BitBoxProtocol.RESPONSE_SUCCESS)) {
                throw new DeviceException("Handshake process request failed.");
            }

            initiatorHandshake.readMessage(startHandshakeReply.data);
            byte[] sendMsg = initiatorHandshake.writeMessage((byte[]) null);

            Response endHandshakeReply = handshakeQuery(sendMsg);
            if(!Arrays.equals(endHandshakeReply.status, BitBoxProtocol.RESPONSE_SUCCESS)) {
                throw new DeviceException("Handshake conclusion failed.");
            }

            PublicKey publicKey = initiatorHandshake.getRemoteStaticPublicKey();
            boolean pairingVerificationRequiredByHost = publicKey == null || !bitBoxNoiseConfig.containsDeviceStaticPubkey(Utils.getRawKeyBytesFromX509(publicKey));
            boolean pairingVerificationRequiredByDevice = Arrays.equals(endHandshakeReply.data, new byte[]{0x01});

            NoiseTransport transport = initiatorHandshake.toTransport();

            if(pairingVerificationRequiredByHost || pairingVerificationRequiredByDevice) {
                Base32 base32 = Base32.builder().get();
                String code = base32.encodeToString(initiatorHandshake.getHash());
                String displayCode = code.substring(0, 5) + " " + code.substring(5, 10) + "\n" + code.substring(10, 15) + " " + code.substring(15, 20);

                if(!bitBoxNoiseConfig.showPairing(displayCode, new BitBoxNoiseConfig.DeviceResponse() {
                    @Override
                    public boolean call() throws DeviceException {
                        byte[] deviceReponse = rawQuery(OP_I_CAN_HAS_PAIRIN_VERIFICASHUN);
                        if(Arrays.equals(deviceReponse, RESPONSE_SUCCESS)) {
                            return true;
                        } else if(Arrays.equals(deviceReponse, RESPONSE_FAILURE)) {
                            return false;
                        }

                        throw new DeviceException("Unexpected pairing response: " + Utils.bytesToHex(deviceReponse));
                    }
                })) {
                    throw new UserRefusedException("Pairing refused by user");
                }

                if(publicKey != null) {
                    bitBoxNoiseConfig.addDeviceStaticPubkey(Utils.getRawKeyBytesFromX509(publicKey));
                }
            }

            return transport;
        } catch(NoSuchPatternException | NoSuchAlgorithmException e) {
            throw new DeviceException("Unsupported algorithm for handshake", e);
        } catch(AEADBadTagException e) {
            throw new DeviceException("Unable to verify authentication tag", e);
        }
    }

    public void noiseConnect(BitBoxNoiseConfig bitBoxNoiseConfig) throws DeviceException {
        this.noiseTransport = createNoiseChannel(bitBoxNoiseConfig);
    }

    public abstract void unlockQuery() throws DeviceException;

    public abstract void cancelOutstandingRequest();

    public static class Response {
        public Response(byte[] status, byte[] data) {
            this.status = status;
            this.data = data;
        }

        public byte[] status;
        public byte[] data;
    }
}
