package com.sparrowwallet.lark.trezor;

import com.sparrowwallet.lark.DeviceException;

import java.util.List;
import java.util.Optional;

/**
 * Interface for storing THP pairing credentials and handling pairing UI.
 *
 * Manages:
 * - Host's static private key (used for all Trezor devices)
 * - Per-device credentials (opaque blobs from Trezor)
 * - Pairing user interaction (optional)
 *
 * Implementations may combine credential storage with pairing UI
 * (similar to BitBoxNoiseConfig pattern), or provide storage-only
 * with default implementations that reject pairing.
 *
 * Implementations may use file-based, database, or OS keychain storage.
 */
public interface TrezorNoiseConfig {

    // ===== Credential Storage Methods =====

    /**
     * Check if a credential exists for the given Trezor device.
     *
     * @param trezorPublicKey The Trezor's static public key (32 bytes)
     * @return true if credential exists
     */
    boolean containsCredential(byte[] trezorPublicKey);

    /**
     * Store a credential for a Trezor device.
     *
     * @param trezorPublicKey The Trezor's static public key (32 bytes)
     * @param credentialBlob The encrypted credential blob from Trezor (opaque)
     */
    void addCredential(byte[] trezorPublicKey, byte[] credentialBlob);

    /**
     * Get the credential blob for a Trezor device.
     *
     * @param trezorPublicKey The Trezor's static public key (32 bytes)
     * @return The credential blob, or empty if not found
     */
    Optional<byte[]> getCredential(byte[] trezorPublicKey);

    /**
     * Get all stored credentials for credential matching.
     * Used to find which credential matches the current device during handshake.
     *
     * @return List of all stored credentials
     */
    List<CredentialMatcher.StoredCredential> getAllCredentials();

    /**
     * Get the host's static private key.
     *
     * @return The host's static private key (32 bytes), or empty if not set
     */
    Optional<byte[]> getHostStaticPrivateKey();

    /**
     * Set the host's static private key.
     *
     * @param privateKey The host's static private key (32 bytes)
     */
    void setHostStaticPrivateKey(byte[] privateKey);

    /**
     * Remove a credential for a Trezor device.
     *
     * @param trezorPublicKey The Trezor's static public key (32 bytes)
     */
    void removeCredential(byte[] trezorPublicKey);

    /**
     * List all stored Trezor public keys.
     *
     * @return List of Trezor public keys (each 32 bytes)
     */
    List<byte[]> listTrezorPublicKeys();

    /**
     * Clear all credentials and keys.
     */
    void clearAll();

    // ===== THP Pairing UI Methods =====

    /**
     * Prompt user to enter a pairing code for Code Entry pairing.
     * This is called when the device shows a code on its screen,
     * and the user must enter it on the host.
     *
     * @return 6-digit pairing code entered by user
     * @throws DeviceException if user cancels or error occurs
     */
    default String promptForPairingCode() throws DeviceException {
        throw new UnsupportedOperationException("THP pairing not supported by this credential store");
    }

    /**
     * Ask user to confirm pairing with a Trezor device.
     * Called before initiating pairing flow.
     *
     * @param deviceInfo Device model and firmware version
     * @return true if user confirms pairing, false if rejected
     * @throws DeviceException if error occurs
     */
    default boolean confirmPairing(String deviceInfo) throws DeviceException {
        throw new UnsupportedOperationException("THP pairing not supported by this credential store");
    }

    /**
     * Display a pairing code to the user.
     * This is called when the host generates a code that should
     * match the code shown on the device screen.
     *
     * @param code 6-digit pairing code to display
     */
    default void displayPairingCode(String code) {
        throw new UnsupportedOperationException("THP pairing not supported by this credential store");
    }

    /**
     * Ask user to select a pairing method when multiple methods are available.
     *
     * @param availableMethods List of supported pairing methods
     * @return Selected pairing method
     * @throws DeviceException if user cancels or error occurs
     */
    default PairingMethod selectPairingMethod(List<PairingMethod> availableMethods) throws DeviceException {
        // Default: prefer Code Entry if available, else first method
        if(availableMethods.contains(PairingMethod.CODE_ENTRY)) {
            return PairingMethod.CODE_ENTRY;
        }
        return availableMethods.get(0);
    }

    /**
     * Notify user that pairing was successful and credential was stored.
     *
     * @param deviceInfo Device information
     */
    default void pairingSuccessful(String deviceInfo) {
        // Optional notification - implementations may ignore
    }

    /**
     * Notify user that pairing failed.
     *
     * @param reason Failure reason
     */
    default void pairingFailed(String reason) {
        // Optional notification - implementations may ignore
    }

    /**
     * Get the host name to use for pairing.
     * This name will be displayed on the Trezor device during pairing.
     *
     * @return Host name
     */
    default String getHostName() {
        return "Lark";
    }

    /**
     * Pairing method enumeration for THP pairing.
     */
    enum PairingMethod {
        /** Code Entry - user enters code shown on device */
        CODE_ENTRY,
        /** QR Code - user scans QR code shown on device */
        QR_CODE,
        /** NFC - pairing via NFC tap */
        NFC
    }
}
