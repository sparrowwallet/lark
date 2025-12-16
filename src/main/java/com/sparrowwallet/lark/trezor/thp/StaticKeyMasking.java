package com.sparrowwallet.lark.trezor.thp;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Static key masking for THP handshake.
 *
 * Trezor's static public key is masked during handshake to prevent tracking:
 * - mask = SHA-256(trezor_static_pubkey || trezor_ephemeral_pubkey)
 * - masked_pubkey = X25519(mask, trezor_static_pubkey)
 *
 * This ensures the static key appears different for each handshake session.
 */
public class StaticKeyMasking {

    private static final byte[] X25519_PUBLIC_KEY_PREFIX = new byte[] {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
    };

    private static final byte[] X25519_PRIVATE_KEY_PREFIX = new byte[] {
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
    };

    /**
     * Compute the masking scalar for Trezor's static public key.
     *
     * The mask is: SHA-256(trezor_static_pubkey || trezor_ephemeral_pubkey)
     *
     * @param trezorStaticPubkey Trezor's static public key (32 bytes)
     * @param trezorEphemeralPubkey Trezor's ephemeral public key (32 bytes)
     * @return 32-byte mask scalar
     */
    public static byte[] computeMask(byte[] trezorStaticPubkey, byte[] trezorEphemeralPubkey) {
        if(trezorStaticPubkey == null || trezorStaticPubkey.length != 32) {
            throw new IllegalArgumentException("Trezor static public key must be 32 bytes");
        }
        if(trezorEphemeralPubkey == null || trezorEphemeralPubkey.length != 32) {
            throw new IllegalArgumentException("Trezor ephemeral public key must be 32 bytes");
        }

        // Concatenate and hash
        byte[] combined = new byte[64];
        System.arraycopy(trezorStaticPubkey, 0, combined, 0, 32);
        System.arraycopy(trezorEphemeralPubkey, 0, combined, 32, 32);

        return Sha256Hash.hash(combined);
    }

    /**
     * Apply masking to Trezor's static public key using X25519 scalar multiplication.
     *
     * masked_pubkey = X25519(mask, trezor_static_pubkey)
     *
     * Uses KeyAgreement.doPhase() which performs scalar multiplication internally.
     *
     * @param mask The 32-byte masking scalar
     * @param trezorStaticPubkey Trezor's static public key (32 bytes)
     * @return Masked public key (32 bytes)
     * @throws GeneralSecurityException if X25519 operations fail
     */
    public static byte[] applyMask(byte[] mask, byte[] trezorStaticPubkey) throws GeneralSecurityException {
        if(mask == null || mask.length != 32) {
            throw new IllegalArgumentException("Mask must be 32 bytes");
        }
        if(trezorStaticPubkey == null || trezorStaticPubkey.length != 32) {
            throw new IllegalArgumentException("Trezor static public key must be 32 bytes");
        }

        // Convert raw bytes to X25519 keys
        PrivateKey maskPrivateKey = rawBytesToX25519PrivateKey(mask);
        PublicKey trezorPublicKey = rawBytesToX25519PublicKey(trezorStaticPubkey);

        // Perform scalar multiplication via KeyAgreement
        KeyAgreement keyAgreement = KeyAgreement.getInstance("X25519");
        keyAgreement.init(maskPrivateKey);
        keyAgreement.doPhase(trezorPublicKey, true);

        // The generated secret is the result of scalar multiplication
        return keyAgreement.generateSecret();
    }

    /**
     * Convert raw 32-byte X25519 public key to PublicKey object.
     */
    private static PublicKey rawBytesToX25519PublicKey(byte[] rawKey) throws GeneralSecurityException {
        // X.509 encoding: prefix + raw key
        byte[] encoded = new byte[X25519_PUBLIC_KEY_PREFIX.length + 32];
        System.arraycopy(X25519_PUBLIC_KEY_PREFIX, 0, encoded, 0, X25519_PUBLIC_KEY_PREFIX.length);
        System.arraycopy(rawKey, 0, encoded, X25519_PUBLIC_KEY_PREFIX.length, 32);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("X25519");
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * Convert raw 32-byte scalar to X25519 PrivateKey object.
     */
    private static PrivateKey rawBytesToX25519PrivateKey(byte[] rawScalar) throws GeneralSecurityException {
        // PKCS#8 encoding: prefix + raw scalar
        byte[] encoded = new byte[X25519_PRIVATE_KEY_PREFIX.length + 32];
        System.arraycopy(X25519_PRIVATE_KEY_PREFIX, 0, encoded, 0, X25519_PRIVATE_KEY_PREFIX.length);
        System.arraycopy(rawScalar, 0, encoded, X25519_PRIVATE_KEY_PREFIX.length, 32);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("X25519");
        return keyFactory.generatePrivate(keySpec);
    }
}
