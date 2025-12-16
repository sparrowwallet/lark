package com.sparrowwallet.lark.trezor;

/**
 * Bidirectional communication interface between Protocol and TrezorDevice.
 *
 * Allows protocols to:
 * - Query device capabilities for callback handling
 * - Notify device of protocol state changes
 */
interface ProtocolCallbacks {

    /**
     * Check if device supports passphrase entry on the device itself.
     *
     * @return true if Capability_PassphraseEntry is available
     */
    boolean isPassphraseEntryAvailable();

    /**
     * Notify that the session ID has changed.
     * Used by v1 protocol for session management (deprecated passphrase state).
     *
     * @param sessionId The new session ID, or null if no session
     */
    void onSessionIdChanged(byte[] sessionId);
}
