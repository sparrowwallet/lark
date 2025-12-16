package com.sparrowwallet.lark.trezor;

import com.sparrowwallet.drongo.OsType;
import com.sparrowwallet.lark.DeviceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.usb4java.*;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;

/**
 * USB transport implementation using LibUsb4Java.
 * Extracted from TrezorDevice to enable protocol composition.
 *
 * Handles raw 64-byte packet I/O over USB bulk transfer endpoints.
 */
public class UsbTransport implements Transport {
    private static final Logger log = LoggerFactory.getLogger(UsbTransport.class);

    private static final byte IN_ENDPOINT = (byte) 0x81;
    private static final byte OUT_ENDPOINT = (byte) 0x01;
    private static final int TREZOR_INTERFACE = 0;
    private static final int PACKET_SIZE = 64;
    private static final int DEFAULT_TIMEOUT = 2000; // ms

    private final Device usbDevice;
    private final DeviceHandle deviceHandle;
    private boolean closed = false;

    /**
     * Create USB transport from libusb Device.
     *
     * @param usbDevice LibUsb device handle
     * @throws DeviceException if device cannot be opened or claimed
     */
    public UsbTransport(Device usbDevice) throws DeviceException {
        this.usbDevice = usbDevice;
        this.deviceHandle = new DeviceHandle();

        int result = LibUsb.open(usbDevice, deviceHandle);
        if(result != LibUsb.SUCCESS) {
            if(result == LibUsb.ERROR_ACCESS && OsType.getCurrent() == OsType.WINDOWS) {
                throw new DeviceException("Could not open Trezor - invalid device driver. " +
                        "Install proper USB driver for Trezor.");
            }
            throw new DeviceException("Could not open Trezor: " + LibUsb.strError(result));
        }

        result = LibUsb.claimInterface(deviceHandle, TREZOR_INTERFACE);
        if(result != LibUsb.SUCCESS) {
            LibUsb.close(deviceHandle);
            throw new DeviceException("Could not claim USB interface: " + LibUsb.strError(result));
        }

        log.debug("USB transport opened successfully");
    }

    @Override
    public void write(byte[] packet) throws DeviceException {
        if(closed) {
            throw new DeviceException("USB transport is closed");
        }

        if(packet.length != PACKET_SIZE) {
            throw new IllegalArgumentException("Packet must be exactly " + PACKET_SIZE + " bytes, got " + packet.length);
        }

        ByteBuffer buffer = BufferUtils.allocateByteBuffer(PACKET_SIZE);
        buffer.put(packet);
        buffer.rewind();

        IntBuffer transferred = IntBuffer.allocate(1);
        int result = LibUsb.bulkTransfer(
                deviceHandle,
                OUT_ENDPOINT,
                buffer,
                transferred,
                DEFAULT_TIMEOUT
        );

        if(result != LibUsb.SUCCESS) {
            if(result == LibUsb.ERROR_TIMEOUT) {
                throw new DeviceException("USB write timeout after " + DEFAULT_TIMEOUT + "ms");
            }
            throw new DeviceException("USB write failed: " + LibUsb.strError(result));
        }

        if(transferred.get(0) != PACKET_SIZE) {
            throw new DeviceException("USB write incomplete: " + transferred.get(0) + " of " + PACKET_SIZE + " bytes");
        }
    }

    @Override
    public byte[] read() throws DeviceException {
        return read(DEFAULT_TIMEOUT);
    }

    @Override
    public byte[] read(int timeoutMs) throws DeviceException {
        if(closed) {
            throw new DeviceException("USB transport is closed");
        }

        ByteBuffer buffer = BufferUtils.allocateByteBuffer(PACKET_SIZE);
        IntBuffer transferred = IntBuffer.allocate(1);

        int result = LibUsb.bulkTransfer(
                deviceHandle,
                IN_ENDPOINT,
                buffer,
                transferred,
                timeoutMs
        );

        if(result == LibUsb.ERROR_TIMEOUT) {
            throw new DeviceTimeoutException("USB read timeout after " + timeoutMs + "ms");
        }

        if(result != LibUsb.SUCCESS) {
            throw new DeviceException("USB read failed: " + LibUsb.strError(result));
        }

        byte[] data = new byte[transferred.get(0)];
        buffer.rewind();
        buffer.get(data);
        return data;
    }

    @Override
    public void close() throws DeviceException {
        if(!closed) {
            if(deviceHandle != null && deviceHandle.getPointer() != 0) {
                try {
                    int result = LibUsb.releaseInterface(deviceHandle, TREZOR_INTERFACE);
                    if(result != LibUsb.SUCCESS) {
                        log.error("Unable to release USB interface, returned " + result);
                    }
                } catch(Exception e) {
                    log.warn("Error releasing USB interface", e);
                }

                try {
                    LibUsb.close(deviceHandle);
                } catch(Exception e) {
                    log.warn("Error closing USB device", e);
                }
            }

            closed = true;
            log.debug("USB transport closed");
        }
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    /**
     * Get the underlying USB device (for device enumeration).
     * Package-private for factory use.
     */
    Device getUsbDevice() {
        return usbDevice;
    }
}
