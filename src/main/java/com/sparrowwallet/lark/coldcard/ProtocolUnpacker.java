package com.sparrowwallet.lark.coldcard;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.lark.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class ProtocolUnpacker extends Protocol {
    public static Object decode(byte[] response) throws DeviceException {
        if(response.length < 4) {
            throw new DeviceProtocolException("Response too short");
        }

        String sign = new String(response, 0, 4, StandardCharsets.UTF_8);
        return switch(sign) {
            case "okay" -> null;
            case "fram" -> throw new DeviceFramingException("Framing error: " + new String(response, 4, response.length - 4, StandardCharsets.UTF_8));
            case "err_" -> throw new DeviceProtocolException("Coldcard returned error: " + new String(response, 4, response.length - 4, StandardCharsets.UTF_8));
            case "refu" -> throw new UserRefusedException();
            case "busy" -> throw new DeviceBusyException();
            case "biny" -> Biny.decode(response).data();
            case "int1" -> Int1.decode(response).int1();
            case "int2" -> Int2.decode(response).getInts();
            case "int3" -> Int3.decode(response).getInts();
            case "asci" -> Asci.decode(response).ascii();
            case "mypb" -> MyPB.decode(response).getDeviceId();
            case "smrx" -> Smrx.decode(response).getSignedMessage();
            case "strx" -> Strx.decode(response).getSignedTransaction();
            default -> throw new DeviceProtocolException("Unknown response: " + sign);
        };
    }

    public record Okay() {

    }

    public record Biny(byte[] data) {
        public static Biny decode(byte[] response) {
            return new Biny(Arrays.copyOfRange(response, 4, response.length));
        }
    }

    public record Int1(long int1) {
        public static Int1 decode(byte[] response) {
            return new Int1(Utils.readUint32(response, 4));
        }
    }

    public record Int2(long int1, long int2) {
        public static Int2 decode(byte[] response) {
            return new Int2(Utils.readUint32(response, 4), Utils.readUint32(response, 8));
        }

        public long[] getInts() {
            return new long[]{int1, int2};
        }
    }

    public record Int3(long int1, long int2, long int3) {
        public static Int3 decode(byte[] response) {
            return new Int3(Utils.readUint32(response, 4), Utils.readUint32(response, 8), Utils.readUint32(response, 12));
        }

        public long[] getInts() {
            return new long[]{int1, int2, int3};
        }
    }

    public record MyPB(byte[] pubKey, byte[] fingerprint, byte[] xpub) {
        public static MyPB decode(byte[] response) {
            byte[] pubKey = Arrays.copyOfRange(response, 4, 68);
            byte[] fingerprint = Arrays.copyOfRange(response, 68, 72);
            long xpubLength = Utils.readUint32(response, 72);
            byte[] xpub = Arrays.copyOfRange(response, response.length - (int)xpubLength, response.length);
            return new MyPB(pubKey, fingerprint, xpub);
        }

        public DeviceId getDeviceId() {
            return new DeviceId(pubKey, fingerprint, xpub);
        }
    }

    public record Asci(String ascii) {
        public static Asci decode(byte[] response) {
            return new Asci(new String(response, 4, response.length - 4, StandardCharsets.US_ASCII));
        }
    }

    public record Smrx(String address, byte[] signature) {
        public static Smrx decode(byte[] response) {
            long aln = Utils.readUint32(response, 4);
            String address = new String(response, 8, (int)aln + 8, StandardCharsets.US_ASCII);
            byte[] signature = Arrays.copyOfRange(response, (int)aln + 8, response.length);
            return new Smrx(address, signature);
        }

        public SignedMessage getSignedMessage() {
            return new SignedMessage(address, signature);
        }
    }

    public record Strx(long length, Sha256Hash sha256) {
        public static Strx decode(byte[] response) {
            long length = Utils.readUint32(response, 4);
            byte[] sha256 = Arrays.copyOfRange(response, 8, response.length);
            return new Strx(length, Sha256Hash.wrap(sha256));
        }

        public SignedTransaction getSignedTransaction() {
            return new SignedTransaction(length, sha256);
        }
    }
}
