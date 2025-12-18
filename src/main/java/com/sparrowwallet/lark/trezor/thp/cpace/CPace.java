package com.sparrowwallet.lark.trezor.thp.cpace;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * CPace (Password-Authenticated Key Exchange) implementation for THP Code Entry pairing.
 *
 * Implements CPace-X25519-SHA512 as specified in draft-irtf-cfrg-cpace-10
 * and adapted for Trezor THP protocol.
 *
 * Reference: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace
 */
public class CPace {

    // CPace DSI (Domain Separation Identifier) for CPace255
    private static final byte[] DSI = "CPace255".getBytes(StandardCharsets.US_ASCII);
    private static final int HASH_BLOCK_SIZE = 128; // SHA-512 block size

    /**
     * Result of CPace calculation.
     */
    public static class Result {
        public final byte[] hostPublicKey;
        public final byte[] tag;
        public final PrivateKey hostPrivateKey;

        public Result(byte[] hostPublicKey, byte[] tag, PrivateKey hostPrivateKey) {
            this.hostPublicKey = hostPublicKey;
            this.tag = tag;
            this.hostPrivateKey = hostPrivateKey;
        }
    }

    /**
     * Perform CPace calculation for Code Entry pairing.
     *
     * @param pairingCode 6-digit pairing code entered by user
     * @param handshakeHash Noise handshake hash (32 bytes)
     * @param trezorPublicKey Trezor's CPace public key (32 bytes)
     * @return CPace result containing host public key and tag
     * @throws GeneralSecurityException if cryptographic operations fail
     */
    public static Result calculate(String pairingCode, byte[] handshakeHash, byte[] trezorPublicKey)
            throws GeneralSecurityException {

        // Convert pairing code to bytes (prs = password/passphrase)
        byte[] prs = pairingCode.getBytes(StandardCharsets.US_ASCII);

        // Step 1: Compute generator point from pairing code
        byte[] generator = computeGenerator(prs, handshakeHash);

        // Step 2: Generate ephemeral key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("X25519");
        KeyPair hostEphemeral = keyGen.generateKeyPair();

        // Step 3: Extract raw private key (32 bytes)
        byte[] hostPrivateKeyRaw = extractRawPrivateKey(hostEphemeral.getPrivate());

        // Step 3b: Clamp private key per RFC 7748 (required for X25519)
        // This ensures the private key is in the correct form for X25519 operations
        clampPrivateKey(hostPrivateKeyRaw);

        // Step 4: Compute host public key = hostPrivate * generator
        byte[] hostPublicKey = x25519Multiply(hostPrivateKeyRaw, generator);

        // Step 5: Compute shared secret = hostPrivate * trezorPublicKey
        byte[] sharedSecret = x25519Multiply(hostPrivateKeyRaw, trezorPublicKey);

        // Step 6: Compute tag = SHA256(sharedSecret)
        byte[] tag = Sha256Hash.hash(sharedSecret);

        return new Result(hostPublicKey, tag, hostEphemeral.getPrivate());
    }

    /**
     * Derive 6-digit pairing code from secret and challenge.
     *
     * @param secret The secret received from device (16 bytes)
     * @param handshakeHash Noise handshake hash (32 bytes)
     * @param challenge Random challenge sent to device (16 bytes)
     * @return 6-digit code as string
     */
    public static String deriveCode(byte[] secret, byte[] handshakeHash, byte[] challenge) {
        // codeInput = method_byte || handshakeHash || secret || challenge
        byte[] codeInput = new byte[1 + handshakeHash.length + secret.length + challenge.length];
        int offset = 0;

        codeInput[offset++] = 0x02; // PairingMethod.CodeEntry = 2

        System.arraycopy(handshakeHash, 0, codeInput, offset, handshakeHash.length);
        offset += handshakeHash.length;

        System.arraycopy(secret, 0, codeInput, offset, secret.length);
        offset += secret.length;

        System.arraycopy(challenge, 0, codeInput, offset, challenge.length);

        // Hash and convert to 6-digit code
        byte[] hash = Sha256Hash.hash(codeInput);
        BigInteger codeInt = new BigInteger(1, hash).mod(BigInteger.valueOf(1_000_000));

        return String.format("%06d", codeInt.intValue());
    }

    /**
     * Compute generator point from pairing code and handshake hash.
     * Implements CPace _generator function.
     *
     * @param prs Password/passphrase (6-digit pairing code as ASCII bytes)
     * @param ci Channel identifier (handshake hash)
     * @return Generator point (32 bytes)
     */
    private static byte[] computeGenerator(byte[] prs, byte[] ci) throws NoSuchAlgorithmException {
        // Build generator string according to CPace spec
        byte[] genStr = buildGeneratorString(prs, ci);

        // Hash with SHA-512 and take first 32 bytes
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] hash = sha512.digest(genStr);
        byte[] preGenerator = Arrays.copyOf(hash, 32);

        // Map to curve point using Elligator2
        return Elligator2.map(preGenerator);
    }

    /**
     * Build generator string according to CPace spec.
     * Format: LV(DSI) || LV(prs) || LV(padding) || LV(ci) || LV(sid)
     * where LV = length-value encoding (LEB128 length prefix)
     */
    private static byte[] buildGeneratorString(byte[] prs, byte[] ci) {
        // Calculate DSI and prs with length prefixes
        byte[] dsiLV = prependLength(DSI);
        byte[] prsLV = prependLength(prs);

        // Calculate padding length
        int lenZpad = Math.max(0, HASH_BLOCK_SIZE - (dsiLV.length + prsLV.length + 1));
        byte[] padding = new byte[lenZpad];
        byte[] paddingLV = prependLength(padding);

        // Build: LV(DSI) || LV(prs) || LV(padding) || LV(ci) || LV(sid)
        // sid is empty (b"")
        byte[] ciLV = prependLength(ci);
        byte[] sidLV = prependLength(new byte[0]);

        // Concatenate all parts
        int totalLen = dsiLV.length + prsLV.length + paddingLV.length + ciLV.length + sidLV.length;
        byte[] result = new byte[totalLen];
        int offset = 0;

        System.arraycopy(dsiLV, 0, result, offset, dsiLV.length);
        offset += dsiLV.length;

        System.arraycopy(prsLV, 0, result, offset, prsLV.length);
        offset += prsLV.length;

        System.arraycopy(paddingLV, 0, result, offset, paddingLV.length);
        offset += paddingLV.length;

        System.arraycopy(ciLV, 0, result, offset, ciLV.length);
        offset += ciLV.length;

        System.arraycopy(sidLV, 0, result, offset, sidLV.length);

        return result;
    }

    /**
     * Prepend LEB128 length encoding (simplified for values < 128).
     */
    private static byte[] prependLength(byte[] data) {
        if(data.length > 127) {
            throw new IllegalArgumentException("Data too long for simple LEB128 encoding");
        }
        byte[] result = new byte[1 + data.length];
        result[0] = (byte) data.length;
        System.arraycopy(data, 0, result, 1, data.length);
        return result;
    }

    /**
     * Extract raw 32-byte private key from PrivateKey object.
     */
    private static byte[] extractRawPrivateKey(PrivateKey privateKey) {
        byte[] encoded = privateKey.getEncoded();
        // PKCS#8 encoding: 16-byte header + 32-byte key
        byte[] raw = new byte[32];
        System.arraycopy(encoded, 16, raw, 0, 32);
        return raw;
    }

    /**
     * Clamp X25519 private key per RFC 7748 Section 5.
     * This is required for proper X25519 operations.
     *
     * - Clear bits 0, 1, 2 of the first byte (make divisible by 8)
     * - Clear bit 7 of the last byte (ensure < 2^255)
     * - Set bit 6 of the last byte (ensure >= 2^254)
     *
     * @param privateKey 32-byte private key to clamp (modified in-place)
     */
    private static void clampPrivateKey(byte[] privateKey) {
        privateKey[0] &= (byte) 0xF8;   // Clear bits 0, 1, 2
        privateKey[31] &= (byte) 0x7F;  // Clear bit 7
        privateKey[31] |= (byte) 0x40;  // Set bit 6
    }

    /**
     * Perform X25519 scalar multiplication: scalar * point.
     *
     * @param scalar 32-byte scalar (private key)
     * @param point 32-byte curve point (public key)
     * @return 32-byte result point
     */
    private static byte[] x25519Multiply(byte[] scalar, byte[] point) throws GeneralSecurityException {
        // Create a temporary KeyPair from the scalar
        byte[] pkcs8 = new byte[48];
        // PKCS#8 header for X25519
        byte[] header = {
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
        };
        System.arraycopy(header, 0, pkcs8, 0, 16);
        System.arraycopy(scalar, 0, pkcs8, 16, 32);

        KeyFactory keyFactory = KeyFactory.getInstance("X25519");
        PrivateKey privateKey = keyFactory.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(pkcs8));

        // Create PublicKey from point
        byte[] x509 = new byte[44];
        // X.509 header for X25519
        byte[] pubHeader = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
        };
        System.arraycopy(pubHeader, 0, x509, 0, 12);
        System.arraycopy(point, 0, x509, 12, 32);

        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(x509));

        // Perform key agreement
        KeyAgreement keyAgreement = KeyAgreement.getInstance("X25519");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);

        return keyAgreement.generateSecret();
    }
}
