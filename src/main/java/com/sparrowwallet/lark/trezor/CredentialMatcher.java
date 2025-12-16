package com.sparrowwallet.lark.trezor;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import javax.crypto.KeyAgreement;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

/**
 * Utility for matching stored credentials to Trezor device during THP handshake.
 *
 * During the Noise handshake, the Trezor's static public key is masked. To find which
 * credential matches, we need to verify the masking using each stored credential.
 *
 * Matching algorithm:
 * 1. mask = SHA256(credential.trezor_pubkey || trezor_ephemeral_pubkey)
 * 2. shared_secret = X25519(mask, credential.trezor_pubkey)
 * 3. Match if shared_secret == trezor_static_masked
 */
public class CredentialMatcher {

    /**
     * Credential storage entry.
     */
    public static class StoredCredential {
        public final byte[] trezorPublicKey;
        public final byte[] hostPrivateKey;
        public final byte[] credentialBlob;

        public StoredCredential(byte[] trezorPublicKey, byte[] hostPrivateKey, byte[] credentialBlob) {
            this.trezorPublicKey = trezorPublicKey;
            this.hostPrivateKey = hostPrivateKey;
            this.credentialBlob = credentialBlob;
        }
    }

    /**
     * Trezor public keys extracted from Noise handshake state.
     */
    public static class TrezorPublicKeys {
        public final byte[] ephemeral;
        public final byte[] staticMasked;

        public TrezorPublicKeys(byte[] ephemeral, byte[] staticMasked) {
            this.ephemeral = ephemeral;
            this.staticMasked = staticMasked;
        }
    }

    /**
     * Find matching credential from a list of stored credentials.
     *
     * @param credentials List of stored credentials to search
     * @param trezorKeys Trezor's ephemeral and masked static keys from handshake
     * @return Matching credential, or null if none found
     */
    public static StoredCredential findCredential(List<StoredCredential> credentials, TrezorPublicKeys trezorKeys) {
        for(StoredCredential cred : credentials) {
            if(matches(cred, trezorKeys)) {
                return cred;
            }
        }
        return null;
    }

    /**
     * Check if a credential matches the Trezor's public keys.
     *
     * @param credential The stored credential to check
     * @param trezorKeys Trezor's ephemeral and masked static keys from handshake
     * @return true if credential matches
     */
    public static boolean matches(StoredCredential credential, TrezorPublicKeys trezorKeys) {
        try {
            // Step 1: Compute mask = SHA256(trezor_pubkey || trezor_ephemeral)
            byte[] maskInput = new byte[credential.trezorPublicKey.length + trezorKeys.ephemeral.length];
            System.arraycopy(credential.trezorPublicKey, 0, maskInput, 0, credential.trezorPublicKey.length);
            System.arraycopy(trezorKeys.ephemeral, 0, maskInput, credential.trezorPublicKey.length, trezorKeys.ephemeral.length);
            byte[] mask = Sha256Hash.hash(maskInput);

            // Step 2: Compute shared_secret = X25519(mask, trezor_pubkey)
            byte[] sharedSecret = x25519KeyAgreement(mask, credential.trezorPublicKey);

            // Step 3: Check if shared_secret == trezor_static_masked
            return Arrays.equals(sharedSecret, trezorKeys.staticMasked);
        } catch(GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Perform X25519 key agreement: scalar * point.
     *
     * @param privateKeyBytes Private key as 32-byte scalar
     * @param publicKeyBytes Public key as 32-byte point
     * @return Shared secret (32 bytes)
     */
    private static byte[] x25519KeyAgreement(byte[] privateKeyBytes, byte[] publicKeyBytes)
            throws GeneralSecurityException {

        KeyFactory keyFactory = KeyFactory.getInstance("X25519");

        // Create PrivateKey from raw bytes
        byte[] pkcs8 = new byte[48];
        byte[] header = {
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
        };
        System.arraycopy(header, 0, pkcs8, 0, 16);
        System.arraycopy(privateKeyBytes, 0, pkcs8, 16, 32);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));

        // Create PublicKey from raw bytes
        byte[] x509 = new byte[44];
        byte[] pubHeader = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
        };
        System.arraycopy(pubHeader, 0, x509, 0, 12);
        System.arraycopy(publicKeyBytes, 0, x509, 12, 32);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(x509));

        // Perform key agreement
        KeyAgreement keyAgreement = KeyAgreement.getInstance("X25519");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);

        return keyAgreement.generateSecret();
    }
}
