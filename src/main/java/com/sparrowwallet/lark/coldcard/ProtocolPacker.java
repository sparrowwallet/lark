package com.sparrowwallet.lark.coldcard;

import com.sparrowwallet.drongo.Utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class ProtocolPacker extends Protocol {
    public static byte[] logout() {
        return pack(LOGO);
    }

    public static byte[] reboot() {
        return pack(REBO);
    }

    public static byte[] version() {
        return pack(VERS);
    }

    public static byte[] ping(String msg) {
        return Utils.concat(PING, msg.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] bip39Passphrase(String passphrase) {
        return Utils.concat(PASS, passphrase.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] passphraseDone() {
        return PWOK;
    }

    public static byte[] checkMitm() {
        return MITM;
    }

    public static byte[] startBackup() {
        return BACK;
    }

    public static byte[] encryptStart(byte[] pubKey) {
        return encryptStart(pubKey, (byte)1);
    }

    public static byte[] encryptStart(byte[] pubKey, byte version) {
        assert pubKey.length == 64;
        ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + 64);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(NCRY);
        buffer.putInt(version);
        buffer.put(pubKey);
        return buffer.array();
    }

    public static byte[] upload(long offset, long totalSize, byte[] data) {
        assert data.length <= MAX_MSG_LEN;
        ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + 4 + data.length);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(UPLD);
        putUnsignedInt(buffer, offset);
        putUnsignedInt(buffer, totalSize);
        buffer.put(data);
        return buffer.array();
    }

    public static byte[] download(long offset, long length, long fileNumber) {
        assert fileNumber >= 0 && fileNumber < 2;
        ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + 4 + 4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(DWLD);
        putUnsignedInt(buffer, offset);
        putUnsignedInt(buffer, length);
        putUnsignedInt(buffer, fileNumber);
        return buffer.array();
    }

    public static byte[] sha256() {
        return SHA2;
    }

    public static byte[] signTransaction(long length, byte[] fileSha, boolean finalize) {
        return signTransaction(length, fileSha, finalize, (byte)0);
    }

    public static byte[] signTransaction(long length, byte[] fileSha, boolean finalize, byte flags) {
        assert fileSha.length == 32;
        flags |= (byte)(finalize ? STXN_FINALIZE : 0);
        ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + 4 + 32);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(STXN);
        putUnsignedInt(buffer, length);
        putUnsignedInt(buffer, flags);
        buffer.put(fileSha);
        return buffer.array();
    }

    public static byte[] signMessage(byte[] rawMsg, String subPath) {
        return signMessage(rawMsg, subPath, AF_CLASSIC);
    }

    public static byte[] signMessage(byte[] rawMsg, String subPath, int addressFormat) {
        ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + 4 + 4 + subPath.length() + rawMsg.length);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(SMSG);
        putUnsignedInt(buffer, addressFormat);
        putUnsignedInt(buffer, subPath.length());
        putUnsignedInt(buffer, rawMsg.length);
        buffer.put(subPath.getBytes(StandardCharsets.US_ASCII));
        buffer.put(rawMsg);
        return buffer.array();
    }

    public static byte[] getSignedMessage() {
        return SMOK;
    }

    public static byte[] getBackupFile() {
        return BKOK;
    }

    public static byte[] getSignedTxn() {
        return STOK;
    }

    public static byte[] multisigEnroll(long length, byte[] fileSha) {
        assert fileSha.length == 32;
        ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + 32);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(ENRL);
        putUnsignedInt(buffer, length);
        buffer.put(fileSha);
        return buffer.array();
    }

    public static byte[] multisigCheck(long n, long m, long xfpXor) {
        ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + 4 + 4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(MSCK);
        putUnsignedInt(buffer, n);
        putUnsignedInt(buffer, m);
        putUnsignedInt(buffer, xfpXor);
        return buffer.array();
    }

    public static byte[] getXpub() {
        return getXpub("m");
    }

    public static byte[] getXpub(String subPath) {
        return Utils.concat(XPUB, subPath.getBytes(StandardCharsets.US_ASCII));
    }

    public static byte[] showAddress(String subPath, long addressFormat) {
        assert (addressFormat & AFC_SCRIPT) == 0;
        ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + subPath.length());
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(SHOW);
        putUnsignedInt(buffer, addressFormat);
        buffer.put(subPath.getBytes(StandardCharsets.US_ASCII));
        return buffer.array();
    }

    public static byte[] showP2SHAddress(byte m, List<long[]> xfpPaths, byte[] witdeemScript, long addressFormat) {
        assert (addressFormat & AFC_SCRIPT) > 0;
        assert witdeemScript.length >= 30 && witdeemScript.length <= 520;

        ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + 1 + 1 + 2 + witdeemScript.length + xfpPaths.stream().mapToInt(value -> 1 + value.length * 4).sum());
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(P2SH);
        putUnsignedInt(buffer, addressFormat);
        buffer.put(m);
        buffer.put((byte)xfpPaths.size());
        putUnsignedShort(buffer, witdeemScript.length);
        buffer.put(witdeemScript);

        for(long[] xfpPath : xfpPaths) {
            buffer.put((byte)xfpPath.length);
            for(long xfp : xfpPath) {
                putUnsignedInt(buffer, xfp);
            }
        }

        return buffer.array();
    }

    public static byte[] blockchain() {
        return BLKC;
    }

    public static byte[] simKeypress() {
        return XKEY;
    }

    public static byte[] bagNumber(byte[] newNumber) {
        return Utils.concat(BAGI, newNumber);
    }

    public static byte[] hsmStart(long length, byte[] fileSha) {
        if(length > 0) {
            assert fileSha.length == 32;
            ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + fileSha.length);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.put(HSMS);
            putUnsignedInt(buffer, length);
            buffer.put(fileSha);
            return buffer.array();
        } else {
            return HSMS;
        }
    }

    public static byte[] hsmStatus() {
        return HSTS;
    }

    public static byte[] createUser(byte[] userName, int authMode, byte[] secret) {
        assert userName.length >= 1 && userName.length <= MAX_USERNAME_LEN;
        assert secret.length == 0 || secret.length == 10 || secret.length == 20 || secret.length == 32;
        ByteBuffer buffer = ByteBuffer.allocate(4 + 1 + 1 + 1 + userName.length + secret.length);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(NWUR);
        buffer.put((byte)authMode);
        buffer.put((byte)userName.length);
        buffer.put((byte)secret.length);
        buffer.put(userName);
        buffer.put(secret);
        return buffer.array();
    }

    public static byte[] deleteUser(byte[] userName) {
        assert userName.length >= 1 && userName.length <= MAX_USERNAME_LEN;
        ByteBuffer buffer = ByteBuffer.allocate(4 + 1 + userName.length);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(RMUR);
        buffer.put((byte)userName.length);
        buffer.put(userName);
        return buffer.array();
    }

    public static byte[] userAuth(byte[] userName, byte[] token, int totpTime) {
        assert userName.length >= 1 && userName.length <= MAX_USERNAME_LEN;
        assert token.length >= 6 && token.length <= 32;
        ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + 1 + 1 + userName.length + token.length);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(USER);
        putUnsignedInt(buffer, totpTime);
        buffer.put((byte)userName.length);
        buffer.put((byte)token.length);
        buffer.put(userName);
        buffer.put(token);
        return buffer.array();
    }

    public static byte[] getStorageLocker() {
        return GSLR;
    }

    private static byte[] pack(byte[] data) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.put(data);
        return buffer.array();
    }

    private static byte[] pack(byte data) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.put(data);
        return buffer.array();
    }

    private static void putUnsignedShort(ByteBuffer buffer, int val) {
        buffer.put((byte) (0xFF & val));
        buffer.put((byte) (0xFF & (val >> 8)));
    }

    private static void putUnsignedInt(ByteBuffer buffer, long val) {
        buffer.put((byte) (0xFF & val));
        buffer.put((byte) (0xFF & (val >> 8)));
        buffer.put((byte) (0xFF & (val >> 16)));
        buffer.put((byte) (0xFF & (val >> 24)));
    }
}
