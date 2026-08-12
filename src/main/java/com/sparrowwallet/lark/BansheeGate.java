package com.sparrowwallet.lark;

import com.fazecast.jSerialComm.SerialPort;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Text line protocol for Banshee firmware (115200 baud USB serial).
 */
public class BansheeGate implements AutoCloseable {
    private static final int BAUD = 115200;
    private static final int DEFAULT_TIMEOUT_MS = 5000;
    private static final int SIGN_TIMEOUT_MS = 70000;
    private static final int MAX_LINE = 65536;

    private final SerialPort serialPort;
    private final InputStream in;
    private final OutputStream out;
    private final String network;

    public BansheeGate(SerialPort serialPort, String network) throws DeviceException {
        if(BansheeClient.BANSHEE_DEVICE_IDS.stream().noneMatch(id -> id.matches(serialPort))) {
            throw new DeviceException("Not a Banshee device");
        }
        this.serialPort = serialPort;
        this.network = network;
        serialPort.setBaudRate(BAUD);
        serialPort.setComPortTimeouts(SerialPort.TIMEOUT_READ_SEMI_BLOCKING, DEFAULT_TIMEOUT_MS, 0);
        if(!serialPort.openPort()) {
            throw new DeviceException("Could not open Banshee serial port");
        }
        try {
            in = serialPort.getInputStream();
            out = serialPort.getOutputStream();
            drainBanner();
            String status = command("WALLET_STATUS");
            if(status.contains("ready=0")) {
                throw new DeviceException("Banshee wallet not initialized. Create a wallet in Banshee Studio first.");
            }
        } catch(IOException e) {
            serialPort.closePort();
            throw new DeviceException("Banshee serial error", e);
        }
    }

    private void drainBanner() throws IOException, DeviceException {
        long deadline = System.currentTimeMillis() + 2000;
        while(System.currentTimeMillis() < deadline) {
            String line = readLine(250);
            if(line.isEmpty()) {
                continue;
            }
            if(line.startsWith("OK READY")) {
                return;
            }
            if(line.startsWith("OK ") || line.startsWith("ERR ")) {
                return;
            }
        }
    }

    public String command(String cmd) throws DeviceException {
        try {
            out.write((cmd + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            String resp = readLine(DEFAULT_TIMEOUT_MS);
            return parseOk(resp);
        } catch(IOException e) {
            throw new DeviceException("Banshee command failed: " + cmd, e);
        }
    }

    public String signPsbt(String psbtBase64) throws DeviceException {
        try {
            out.write(("SIGN_PSBT " + network + " " + psbtBase64 + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            String wait = readLine(DEFAULT_TIMEOUT_MS);
            parseOk(wait);
            if(!wait.contains("WAIT")) {
                throw new DeviceException("Unexpected Banshee sign response: " + wait);
            }
            String signed = readLine(SIGN_TIMEOUT_MS);
            if(signed.startsWith("ERR ")) {
                if(signed.contains("timeout")) {
                    throw new DeviceException("Signing timed out on Banshee (press BOOT to confirm)");
                }
                throw new DeviceException(signed.substring(4));
            }
            return parseOkPrefix(signed, "PSBT ");
        } catch(IOException e) {
            throw new DeviceException("Banshee sign failed", e);
        }
    }

    public String getFingerprint() throws DeviceException {
        return parseOkPrefix(command("GET_FINGERPRINT"), "FINGERPRINT ");
    }

    public String getXpub(String path) throws DeviceException {
        String normalized = path.replace('\'', 'h');
        return parseOkPrefix(command("GET_XPUB " + network + " " + normalized), "XPUB ");
    }

    private static String parseOk(String line) throws DeviceException {
        if(line.startsWith("ERR ")) {
            throw new DeviceException(line.substring(4));
        }
        if(!line.startsWith("OK ")) {
            throw new DeviceException(line.isEmpty() ? "Banshee timeout" : line);
        }
        return line.substring(3);
    }

    private static String parseOkPrefix(String line, String prefix) throws DeviceException {
        String rest = parseOk(line.startsWith("OK ") ? line : "OK " + line);
        if(!rest.startsWith(prefix)) {
            throw new DeviceException("Unexpected Banshee response: " + line);
        }
        return rest.substring(prefix.length()).trim();
    }

    private String readLine(int timeoutMs) throws IOException {
        List<Byte> buf = new ArrayList<>();
        long deadline = System.currentTimeMillis() + timeoutMs;
        while(System.currentTimeMillis() < deadline) {
            if(in.available() > 0) {
                int b = in.read();
                if(b < 0) {
                    break;
                }
                if(b == '\r') {
                    continue;
                }
                if(b == '\n') {
                    return new String(toBytes(buf), StandardCharsets.UTF_8).trim();
                }
                if(buf.size() < MAX_LINE) {
                    buf.add((byte)b);
                }
            } else {
                try {
                    Thread.sleep(5);
                } catch(InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        return "";
    }

    private static byte[] toBytes(List<Byte> bytes) {
        byte[] arr = new byte[bytes.size()];
        for(int i = 0; i < bytes.size(); i++) {
            arr[i] = bytes.get(i);
        }
        return arr;
    }

    @Override
    public void close() {
        if(serialPort.isOpen()) {
            serialPort.closePort();
        }
    }
}
