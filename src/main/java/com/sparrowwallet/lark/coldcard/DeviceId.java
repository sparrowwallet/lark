package com.sparrowwallet.lark.coldcard;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.crypto.ECKey;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public record DeviceId(byte[] remotePubKey, byte[] masterFingerprint, byte[] xpub) {
    public ECKey getRemotePubKey() {
        byte[] uncompressedPubKey = new byte[65];
        uncompressedPubKey[0] = 0x04;
        System.arraycopy(remotePubKey, 0, uncompressedPubKey, 1, remotePubKey.length);
        return ECKey.fromPublicOnly(uncompressedPubKey);
    }

    public ExtendedKey getMasterXpub() {
        return ExtendedKey.fromDescriptor(new String(xpub, StandardCharsets.UTF_8));
    }

    public byte[] getPubKeyString() {
        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

        byte[] pubkey = getMasterXpub().getKey().getPubKey();
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(pubkey, 1, pubkey.length));
        BigInteger y = x.modPow(BigInteger.valueOf(3), p).add(BigInteger.valueOf(7)).mod(p).modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);

        if (!y.testBit(0) == ((pubkey[0] & 1) == 1)) {
            y = p.subtract(y);
        }

        ByteBuffer buffer = ByteBuffer.allocate(65);
        buffer.put((byte)4);
        buffer.put(x.toByteArray(), 1, 32);
        buffer.put(y.toByteArray(), 1, 32);

        return buffer.array();
    }
}
