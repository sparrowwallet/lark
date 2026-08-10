package com.sparrowwallet.lark.yubikey;

import com.sparrowwallet.drongo.crypto.ChallengeResponseException;
import com.sparrowwallet.drongo.crypto.ChallengeResponseProvider;
import org.hid4java.HidDevice;
import org.hid4java.HidManager;
import org.hid4java.HidServices;
import org.hid4java.HidServicesSpecification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.usb4java.*;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class YubiKeyHmacProvider implements ChallengeResponseProvider {
    private static final Logger log = LoggerFactory.getLogger(YubiKeyHmacProvider.class);

    private Runnable onWaitingForTouch;
    private Runnable onComplete;

    private static final int CRC_OK_RESIDUAL = 0xF0B8;

    private static final int YUBICO_VID = 0x1050;
    private static final int HID_USAGE_PAGE_OTP = 0x0001;

    private static final int FEATURE_RPT_SIZE = 8;
    private static final int DATA_PER_CHUNK = 7;
    private static final int FRAME_SIZE = 70;
    private static final int SHA1_MAX_BLOCK_SIZE = 64;
    private static final int HMAC_SHA1_RESPONSE_LENGTH = 20;

    private static final byte SLOT_CHAL_HMAC2 = 0x38;

    private static final int SEQUENCE_MASK = 0x1F;
    private static final int RESP_TIMEOUT_WAIT_FLAG = 0x20;
    private static final int RESP_PENDING_FLAG = 0x40;
    private static final byte SLOT_WRITE_FLAG = (byte)0x80;
    private static final byte DUMMY_REPORT_WRITE = (byte)0x8f;

    private static final byte HID_GET_REPORT = 0x01;
    private static final byte HID_SET_REPORT = 0x09;
    private static final short REPORT_TYPE_FEATURE = 0x03;

    private static final int WRITE_TIMEOUT = 1150;
    private static final int USB_TIMEOUT = 1000;

    private static final int[] YUBIKEY_PIDS = {
            0x0010, 0x0110, 0x0111, 0x0114, 0x0116,
            0x0401, 0x0403, 0x0405, 0x0407, 0x0410
    };

    @Override
    public byte[] getResponse(byte[] challenge) throws ChallengeResponseException {
        boolean[] kernelDriverDetached = {false};
        Context context = new Context();
        int result = LibUsb.init(context);
        if(result != LibUsb.SUCCESS) {
            throw new ChallengeResponseException("Failed to initialize libusb: " + LibUsb.errorName(result));
        }

        try {
            DeviceHandle handle = openYubiKey(context, kernelDriverDetached);
            try {
                return performChallengeResponse(handle, challenge);
            } finally {
                LibUsb.releaseInterface(handle, 0);
                if(kernelDriverDetached[0]) {
                    LibUsb.attachKernelDriver(handle, 0);
                }
                LibUsb.close(handle);
            }
        } finally {
            LibUsb.exit(context);
        }
    }

    @Override
    public String getName() {
        return "YubiKey";
    }

    public void setOnWaitingForTouch(Runnable onWaitingForTouch) {
        this.onWaitingForTouch = onWaitingForTouch;
    }

    public void setOnComplete(Runnable onComplete) {
        this.onComplete = onComplete;
    }

    public static boolean isYubiKeyPresent() {
        HidServicesSpecification spec = new HidServicesSpecification();
        spec.setAutoStart(false);
        spec.setAutoShutdown(false);
        HidServices hidServices = HidManager.getHidServices(spec);

        try {
            for(HidDevice device : hidServices.getAttachedHidDevices()) {
                if(device.getVendorId() == YUBICO_VID && device.getUsagePage() == HID_USAGE_PAGE_OTP) {
                    return true;
                }
            }
            return false;
        } finally {
            hidServices.shutdown();
        }
    }

    private DeviceHandle openYubiKey(Context context, boolean[] kernelDriverDetached) throws ChallengeResponseException {
        DeviceList list = new DeviceList();
        int result = LibUsb.getDeviceList(context, list);
        if(result < 0) {
            throw new ChallengeResponseException("Failed to enumerate USB devices: " + LibUsb.errorName(result));
        }

        try {
            for(Device device : list) {
                DeviceDescriptor desc = new DeviceDescriptor();
                result = LibUsb.getDeviceDescriptor(device, desc);
                if(result != LibUsb.SUCCESS) {
                    continue;
                }
                if(desc.idVendor() == (short)YUBICO_VID && isYubiKeyPid(desc.idProduct() & 0xFFFF)) {
                    DeviceHandle handle = new DeviceHandle();
                    result = LibUsb.open(device, handle);
                    if(result != LibUsb.SUCCESS) {
                        throw new ChallengeResponseException("Failed to open security key: " + LibUsb.errorName(result));
                    }

                    int active = LibUsb.kernelDriverActive(handle, 0);
                    if(active == 1) {
                        result = LibUsb.detachKernelDriver(handle, 0);
                        if(result != LibUsb.SUCCESS) {
                            LibUsb.close(handle);
                            throw new ChallengeResponseException("Failed to detach kernel driver: " + LibUsb.errorName(result));
                        }
                        kernelDriverDetached[0] = true;
                    }

                    result = LibUsb.claimInterface(handle, 0);
                    if(result != LibUsb.SUCCESS) {
                        if(kernelDriverDetached[0]) {
                            LibUsb.attachKernelDriver(handle, 0);
                        }
                        LibUsb.close(handle);
                        throw new ChallengeResponseException("Failed to claim security key interface: " + LibUsb.errorName(result));
                    }

                    return handle;
                }
            }
        } finally {
            LibUsb.freeDeviceList(list, true);
        }

        throw new ChallengeResponseException("No compatible security key found. Please plug in your security key and try again.");
    }

    private static boolean isYubiKeyPid(int pid) {
        for(int p : YUBIKEY_PIDS) {
            if(p == pid) {
                return true;
            }
        }
        return false;
    }

    private byte[] performChallengeResponse(DeviceHandle handle, byte[] challenge) throws ChallengeResponseException {
        byte[] frame = buildChallengeFrame(challenge);
        try {
            writeFrame(handle, frame);
            boolean success = false;
            try {
                byte[] response = readResponse(handle);
                success = true;
                forceKeyUpdate(handle);
                return response;
            } finally {
                if(!success) {
                    forceKeyUpdate(handle);
                }
                if(onComplete != null) {
                    onComplete.run();
                }
            }
        } finally {
            Arrays.fill(frame, (byte) 0);
        }
    }

    private byte[] buildChallengeFrame(byte[] challenge) {
        byte[] frame = new byte[FRAME_SIZE];
        int len = Math.min(challenge.length, SHA1_MAX_BLOCK_SIZE);
        System.arraycopy(challenge, 0, frame, 0, len);
        frame[SHA1_MAX_BLOCK_SIZE] = SLOT_CHAL_HMAC2;
        int crc = crc16(frame, SHA1_MAX_BLOCK_SIZE);
        frame[SHA1_MAX_BLOCK_SIZE + 1] = (byte)(crc & 0xFF);
        frame[SHA1_MAX_BLOCK_SIZE + 2] = (byte)((crc >> 8) & 0xFF);
        return frame;
    }

    private void writeFrame(DeviceHandle handle, byte[] frame) throws ChallengeResponseException {
        waitForClear(handle, SLOT_WRITE_FLAG);

        int totalChunks = (FRAME_SIZE + DATA_PER_CHUNK - 1) / DATA_PER_CHUNK;
        for(int seq = 0; seq < totalChunks; seq++) {
            int offset = seq * DATA_PER_CHUNK;
            byte[] report = new byte[FEATURE_RPT_SIZE];
            boolean allZeros = true;
            for(int i = 0; i < DATA_PER_CHUNK && (offset + i) < FRAME_SIZE; i++) {
                report[i] = frame[offset + i];
                if(report[i] != 0) {
                    allZeros = false;
                }
            }

            if(allZeros && seq > 0 && seq < totalChunks - 1) {
                continue;
            }

            report[FEATURE_RPT_SIZE - 1] = (byte)(seq | SLOT_WRITE_FLAG);

            waitForClear(handle, SLOT_WRITE_FLAG);
            usbWrite(handle, report);
        }
    }

    private byte[] readResponse(DeviceHandle handle) throws ChallengeResponseException {
        byte[] firstData = waitForSet(handle, RESP_PENDING_FLAG, true);

        int responseLen = HMAC_SHA1_RESPONSE_LENGTH + 2;
        byte[] response = new byte[responseLen + 8];
        int bytesRead = 0;

        System.arraycopy(firstData, 0, response, 0, DATA_PER_CHUNK);
        Arrays.fill(firstData, (byte) 0);
        bytesRead += DATA_PER_CHUNK;

        while(bytesRead + DATA_PER_CHUNK <= response.length) {
            byte[] data = usbRead(handle);
            try {
                int flags = data[FEATURE_RPT_SIZE - 1] & 0xFF;
                if((flags & RESP_PENDING_FLAG) == 0 || (flags & SEQUENCE_MASK) == 0) {
                    break;
                }
                System.arraycopy(data, 0, response, bytesRead, DATA_PER_CHUNK);
                bytesRead += DATA_PER_CHUNK;
            } finally {
                Arrays.fill(data, (byte) 0);
            }
        }

        if(bytesRead < responseLen) {
            Arrays.fill(response, (byte) 0);
            throw new ChallengeResponseException("Incomplete response from security key: expected " + responseLen + " bytes, got " + bytesRead);
        }

        int crc = crc16(response, responseLen);
        if(crc != CRC_OK_RESIDUAL) {
            Arrays.fill(response, (byte) 0);
            throw new ChallengeResponseException("CRC validation failed on security key response");
        }

        byte[] result = new byte[HMAC_SHA1_RESPONSE_LENGTH];
        System.arraycopy(response, 0, result, 0, HMAC_SHA1_RESPONSE_LENGTH);
        Arrays.fill(response, (byte) 0);
        return result;
    }

    private void forceKeyUpdate(DeviceHandle handle) {
        byte[] buf = new byte[FEATURE_RPT_SIZE];
        buf[FEATURE_RPT_SIZE - 1] = DUMMY_REPORT_WRITE;
        try {
            usbWrite(handle, buf);
        } catch(ChallengeResponseException e) {
            log.debug("Force key update write failed", e);
        }
    }

    private void waitForClear(DeviceHandle handle, int mask) throws ChallengeResponseException {
        long sleepMs = 1;
        long sleptMs = 0;
        while(sleptMs < WRITE_TIMEOUT) {
            sleep(sleepMs);
            sleptMs += sleepMs;
            sleepMs = Math.min(sleepMs * 2, 500);

            byte[] data = usbRead(handle);
            int flags = data[FEATURE_RPT_SIZE - 1] & 0xFF;
            Arrays.fill(data, (byte) 0);
            if((flags & mask) == 0) {
                return;
            }
        }
        throw new ChallengeResponseException("Security key not ready");
    }

    private byte[] waitForSet(DeviceHandle handle, int mask, boolean mayBlock) throws ChallengeResponseException {
        long sleepMs = 1;
        long sleptMs = 0;
        long maxTimeMs = 1000;
        boolean blocking = false;

        while(sleptMs < maxTimeMs) {
            sleep(sleepMs);
            sleptMs += sleepMs;
            sleepMs = Math.min(sleepMs * 2, 500);

            byte[] data = usbRead(handle);
            int flags = data[FEATURE_RPT_SIZE - 1] & 0xFF;

            if((flags & RESP_TIMEOUT_WAIT_FLAG) == RESP_TIMEOUT_WAIT_FLAG) {
                if(mayBlock) {
                    if(!blocking) {
                        blocking = true;
                        maxTimeMs += 256 * 1000L;
                        if(onWaitingForTouch != null) {
                            onWaitingForTouch.run();
                        }
                    }
                } else {
                    forceKeyUpdate(handle);
                    throw new ChallengeResponseException("Security key requires button press but blocking not allowed");
                }
            }

            if((flags & mask) == mask) {
                return data;
            }

            if(blocking && (flags & RESP_TIMEOUT_WAIT_FLAG) == 0) {
                Arrays.fill(data, (byte) 0);
                forceKeyUpdate(handle);
                throw new ChallengeResponseException("Security key timed out waiting for touch. Please try again.");
            }

            Arrays.fill(data, (byte) 0);
        }

        forceKeyUpdate(handle);
        throw new ChallengeResponseException("Timed out waiting for security key response. Please try again.");
    }

    private void usbWrite(DeviceHandle handle, byte[] data) throws ChallengeResponseException {
        ByteBuffer buffer = ByteBuffer.allocateDirect(FEATURE_RPT_SIZE);
        try {
            buffer.put(data, 0, FEATURE_RPT_SIZE);
            buffer.rewind();

            int result = LibUsb.controlTransfer(handle,
                    (byte)(LibUsb.REQUEST_TYPE_CLASS | LibUsb.RECIPIENT_INTERFACE | LibUsb.ENDPOINT_OUT),
                    HID_SET_REPORT,
                    (short)((REPORT_TYPE_FEATURE << 8) | 0x00),
                    (short)0,
                    buffer,
                    USB_TIMEOUT);

            if(result < 0) {
                throw new ChallengeResponseException("Failed to write to security key: " + LibUsb.errorName(result));
            }
        } finally {
            zeroBuffer(buffer);
        }
    }

    private byte[] usbRead(DeviceHandle handle) throws ChallengeResponseException {
        ByteBuffer buffer = ByteBuffer.allocateDirect(FEATURE_RPT_SIZE);
        try {
            int result = LibUsb.controlTransfer(handle,
                    (byte)(LibUsb.REQUEST_TYPE_CLASS | LibUsb.RECIPIENT_INTERFACE | LibUsb.ENDPOINT_IN),
                    HID_GET_REPORT,
                    (short)((REPORT_TYPE_FEATURE << 8) | 0x00),
                    (short)0,
                    buffer,
                    USB_TIMEOUT);

            if(result < 0) {
                throw new ChallengeResponseException("Failed to read from security key: " + LibUsb.errorName(result));
            }

            byte[] data = new byte[FEATURE_RPT_SIZE];
            buffer.get(data, 0, Math.min(result, FEATURE_RPT_SIZE));
            return data;
        } finally {
            zeroBuffer(buffer);
        }
    }

    private static void zeroBuffer(ByteBuffer buffer) {
        for(int i = 0; i < buffer.capacity(); i++) {
            buffer.put(i, (byte) 0);
        }
    }

    private static void sleep(long ms) throws ChallengeResponseException {
        try {
            Thread.sleep(ms);
        } catch(InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ChallengeResponseException("Interrupted while waiting for security key");
        }
    }

    private static int crc16(byte[] data, int len) {
        int crc = 0xFFFF;
        for(int i = 0; i < len; i++) {
            crc ^= data[i] & 0xFF;
            for(int j = 0; j < 8; j++) {
                if((crc & 1) != 0) {
                    crc = (crc >> 1) ^ 0x8408;
                } else {
                    crc >>= 1;
                }
            }
        }
        return crc & 0xFFFF;
    }
}
