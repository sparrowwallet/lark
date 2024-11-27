package com.sparrowwallet.lark.coldcard;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.bip47.SecretPoint;
import com.sparrowwallet.drongo.crypto.ECDSASignature;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.lark.*;
import org.hid4java.HidDevice;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;

import static com.sparrowwallet.lark.coldcard.Constants.MAX_MSG_LEN;

public class ColdcardDevice implements Closeable {
    private static final Logger log = LoggerFactory.getLogger(ColdcardDevice.class);

    public static final int COINKITE_VID = 0xd13e;
    public static final int CKCC_PID     = 0xcc10;
    public static final int DEFAULT_TIMEOUT = 3000;

    private HidDevice hidDevice;
    private String serialNumber;
    private ECKey localKey;
    private byte[] localPubKey;
    private byte[] sessionKey;
    private DeviceId deviceId;
    private Cipher encryptCipher;
    private Cipher decryptCipher;

    public ColdcardDevice(HidDevice hidDevice) throws DeviceException {
        this.hidDevice = hidDevice;
        this.serialNumber = hidDevice.getSerialNumber();

        hidDevice.open();
        resync();

        startEncryption();
    }

    public void resync() throws DeviceException {
        try {
            while(true) {
                int read = hidDevice.read(new byte[64], 1);
                if(read <= 0) {
                    break;
                }
            }

            byte[] zeroLengthPacket = new byte[64];
            Arrays.fill(zeroLengthPacket, (byte) 0xFF);
            zeroLengthPacket[0] = (byte)0x80;
            hidDevice.write(zeroLengthPacket, zeroLengthPacket.length, (byte)0);

            while(true) {
                int read = hidDevice.read(new byte[64], 1);
                if(read <= 0) {
                    break;
                }
            }
        } catch(Exception e) {
            throw new DeviceException(e.getMessage(), e);
        }

        String lastError = hidDevice.getLastErrorMessage();
        if(lastError != null && !lastError.equals("S")) {
            throw new DeviceException("HID returned error of " + lastError);
        }

        if(!hidDevice.getSerialNumber().equals(serialNumber)) {
            throw new DeviceException("Serial number did not match");
        }
    }

    @Override
    public void close() {
        if(hidDevice != null) {
            hidDevice.close();
            hidDevice = null;
        }
    }

    public Object sendRecv(byte[] msg) throws DeviceException {
        return sendRecv(msg, true);
    }

    public Object sendRecv(byte[] msg, boolean encrypt) throws DeviceException {
        return sendRecv(msg, encrypt, DEFAULT_TIMEOUT);
    }

    public Object sendRecv(byte[] msg, boolean encrypt, int timeout) throws DeviceException {
        assert msg.length >= 4 && msg.length <= MAX_MSG_LEN : "msg length: " + msg.length;

        if(encryptCipher == null || decryptCipher == null) {
            encrypt = false; // disable encryption if not already enabled for this connection
        }

        if(encrypt) {
            msg = encryptCipher.update(msg);
        }

        int left = msg.length;
        int offset = 0;
        ByteArrayOutputStream response = new ByteArrayOutputStream();

        while(left > 0) {
            int here = Math.min(63, left);
            byte[] buf = new byte[64];
            System.arraycopy(msg, offset, buf, 1, here);

            if (here == left) {
                // final one in sequence
                buf[0] = (byte) (here | 0x80 | (encrypt ? 0x40 : 0x00));
            } else {
                // more will be coming
                buf[0] = (byte) here;
            }

            log.debug("Tx [" + here + "]: " + Utils.bytesToHex(buf) + " (0x" + Integer.toHexString(buf[0] & 0xFF) + ")");

            int rv = hidDevice.write(buf, buf.length, (byte)0);
            assert rv == buf.length + 1;

            offset += here;
            left -= here;
        }

        byte flag;
        do {
            Byte[] buf = hidDevice.read(64, timeout != 0 ? timeout : 1000);

            if (buf.length == 0 && timeout != 0) {
                // give it another try
                buf = hidDevice.read(64, timeout);
            }

            assert buf.length != 0 : "timeout reading USB EP";

            flag = buf[0];
            byte[] readBuf = new byte[buf.length];
            for(int i = 0; i < buf.length; i++) {
                readBuf[i] = buf[i];
            }

            try {
                response.write(Arrays.copyOfRange(readBuf, 1, 1 + (flag & 0x3F)));
            } catch(IOException e) {
                throw new DeviceProtocolException("Error reading from Coldcard");
            }
        } while((flag & 0x80) == 0);

        byte[] responseArray;
        if((flag & 0x40) != 0) {
            log.debug("Enc response: " + Utils.bytesToHex(response.toByteArray()));
            responseArray = decryptCipher.update(response.toByteArray());
        } else {
            responseArray = response.toByteArray();
        }

        log.debug("Rx [" + responseArray.length + "]: " + Utils.bytesToHex(responseArray));

        return ProtocolUnpacker.decode(responseArray);
    }

    private void startEncryption() throws DeviceException {
        this.localKey = new ECKey();
        this.localPubKey = Arrays.copyOfRange(localKey.getPubKey(false), 1, 65);

        byte[] msg = ProtocolPacker.encryptStart(localPubKey);

        this.deviceId = (DeviceId)sendRecv(msg, false);

        try {
            ECKey remotePubKey = deviceId.getRemotePubKey();
            new SecretPoint(localKey.getPrivKeyBytes(), remotePubKey.getPubKey());
            ECKey ecKey = remotePubKey.multiply(localKey.getPrivKey());
            byte[] secretBytes = ecKey.getPubKey();

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            this.sessionKey = digest.digest(Arrays.copyOfRange(secretBytes, 1, secretBytes.length));

            setupCiphers(sessionKey);
        } catch(Exception e) {
            throw new DeviceInitializationException("Could not determine session key", e);
        }
    }

    private void setupCiphers(byte[] sessionKey) {
        this.encryptCipher = createCipher(sessionKey, Cipher.ENCRYPT_MODE);
        this.decryptCipher = createCipher(sessionKey, Cipher.DECRYPT_MODE);
    }

    private Cipher createCipher(byte[] sessionKey, int mode) {
        try {
            Key key = new SecretKeySpec(sessionKey, "AES");
            byte[] counter = new byte[16];
            IvParameterSpec iv = new IvParameterSpec(counter);

            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(mode, key, iv);

            return cipher;
        } catch(NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public void checkMitm() throws DeviceException {
        byte[] signatureBytes = (byte[])sendRecv(ProtocolPacker.checkMitm(), true, 5000);

        ECKey xpub = ECKey.fromPublicOnly(deviceId.getPubKeyString());

        byte[] rBytes = new byte[32];
        byte[] sBytes = new byte[32];

        ByteBuffer buffer = ByteBuffer.wrap(signatureBytes);
        buffer.get(); // Skip the sign byte (0x30)
        buffer.get(rBytes, 0, 32);
        buffer.get(sBytes, 0, 32);

        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        ECDSASignature signature = new ECDSASignature(r, s);

        if(!signature.verify(sessionKey, xpub.getPubKey())) {
            throw new DeviceMitmFailedException("Failed to verify signature - possible MitM attack!");
        }
    }

    public Upload uploadFile(byte[] data) throws DeviceException {
        return uploadFile(data, true, 1024);
    }

    public Upload uploadFile(byte[] data, boolean verify, int blkSize) throws DeviceException {
        Sha256Hash chk = Sha256Hash.of(data);

        for(int i = 0; i < data.length; i += blkSize) {
            byte[] here = Arrays.copyOfRange(data, i, Math.min(i + blkSize, data.length));
            Long uploaded = (Long)sendRecv(ProtocolPacker.upload(i, data.length, here));
            if(uploaded != i) {
                throw new DeviceProtocolException("Uploaded size " + uploaded + " != " + i);
            }
        }

        if(verify) {
            Sha256Hash received = Sha256Hash.wrap((byte[])sendRecv(ProtocolPacker.sha256()));
            if(!received.equals(chk)) {
                throw new DeviceProtocolException("Checksum wrong during file upload");
            }
        }

        return new Upload(data.length, chk);
    }

    public byte[] downloadFile(long length, Sha256Hash checksum) throws DeviceException {
        return downloadFile(length, checksum, 1024, 1);
    }

    public byte[] downloadFile(long length, Sha256Hash checksum, int blkSize, int fileNumber) throws DeviceException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        MessageDigest digest = Sha256Hash.newDigest();

        long pos = 0;
        while(pos < length) {
            byte[] here = (byte[])sendRecv(ProtocolPacker.download(pos, Math.min(blkSize, length-pos), fileNumber));
            baos.write(here, 0, here.length);
            pos += here.length;
            digest.update(here);
        }

        if(Sha256Hash.wrap(digest.digest()).equals(checksum)) {
            return baos.toByteArray();
        } else {
            throw new DeviceProtocolException("Checksum wrong during file download");
        }
    }

    public DeviceId getDeviceId() {
        return deviceId;
    }

    public HidDevice getHidDevice() {
        return hidDevice;
    }

    public record Upload(int length, Sha256Hash checksum) {}
}
