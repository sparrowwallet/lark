package com.sparrowwallet.lark.trezor;

import com.sparrowwallet.lark.DeviceException;

/**
 * Low-level transport abstraction for communication with Trezor devices.
 * Handles raw packet I/O without protocol-specific logic.
 *
 * Implementations provide the physical layer (USB, Bluetooth, etc.)
 * while protocols (v1, THP) handle message framing and encryption.
 */
public interface Transport extends AutoCloseable {

    /**
     * Write a packet to the device.
     *
     * @param packet The packet data to write (typically 64 bytes for USB)
     * @throws DeviceException if write fails
     */
    void write(byte[] packet) throws DeviceException;

    /**
     * Read a packet from the device with default timeout.
     *
     * @return The packet data read from the device
     * @throws DeviceException if read fails or times out
     */
    byte[] read() throws DeviceException;

    /**
     * Read a packet from the device with specified timeout.
     *
     * @param timeoutMs Timeout in milliseconds
     * @return The packet data read from the device
     * @throws DeviceException if read fails or times out
     */
    byte[] read(int timeoutMs) throws DeviceException;

    /**
     * Close the transport and release resources.
     * Should be idempotent (safe to call multiple times).
     */
    @Override
    void close() throws DeviceException;

    /**
     * Check if transport is closed.
     *
     * @return true if closed, false otherwise
     */
    boolean isClosed();
}
