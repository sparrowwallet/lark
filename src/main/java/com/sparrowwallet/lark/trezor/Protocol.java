package com.sparrowwallet.lark.trezor;

import com.google.protobuf.Message;
import com.sparrowwallet.lark.DeviceException;

/**
 * Protocol abstraction for Trezor communication.
 *
 * Implementations handle protocol-specific message framing, encoding,
 * and transport over the wire. Does not contain application logic.
 *
 * Current implementations:
 * - V1Protocol: Unencrypted Codec v1 (?## header + type + length)
 * - V2Protocol (THP): Encrypted transport (control byte + CID + CRC + Noise)
 */
interface Protocol {

    /**
     * Send a message and receive a response with automatic callback handling.
     * Handles PIN, passphrase, and button request callbacks via TrezorUI.
     *
     * @param request The protobuf message to send
     * @param responseType Expected response type
     * @param <T> Response message type
     * @return The response message
     * @throws DeviceException if communication fails or device returns error
     */
    <T extends Message> T call(Message request, Class<T> responseType) throws DeviceException;

    /**
     * Send a message and receive a raw response without callback handling.
     * Used for low-level operations like Initialize, Ping, and probing.
     *
     * @param request The protobuf message to send
     * @return The raw response message
     * @throws DeviceException if communication fails
     */
    Message callRaw(Message request) throws DeviceException;

    /**
     * Close the protocol and release resources.
     */
    void close();
}
