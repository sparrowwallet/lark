package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class BitBox02SignatureTest {
    private static final String LOW_S = "7fd66b48ffea2fe048869880bbb3a1819e262af14980e8885df1e5765750cb8f47e01eca356377870356d54853573a955076228e5044cd3dd3a049abe70d5585";
    private static final String HIGH_S = "7fd66b48ffea2fe048869880bbb3a1819e262af14980e8885df1e5765750cb8fb81fe135ca9c8878fca92ab7aca8c5696a38ba585f03d2fdec3214e0e928ebbc";

    @Test
    public void testCompactSignature() {
        byte[] signature = Utils.hexToBytes(LOW_S);
        assertDoesNotThrow(() -> BitBox02Client.verifyCompactSignature(signature));
        assertThrows(DeviceException.class, () -> BitBox02Client.verifyCompactSignature(Utils.hexToBytes(HIGH_S)));

        assertThrows(DeviceException.class, () -> BitBox02Client.verifyCompactSignature(Arrays.copyOfRange(signature, 0, 63)));
        assertThrows(DeviceException.class, () -> BitBox02Client.verifyCompactSignature(Arrays.copyOf(signature, 65)));

        byte[] curveOrder = Utils.bigIntegerToBytes(ECKey.CURVE_ORDER, 32);
        for(int offset : new int[] {0, 32}) {
            byte[] zeroScalar = signature.clone();
            Arrays.fill(zeroScalar, offset, offset + 32, (byte)0);
            assertThrows(DeviceException.class, () -> BitBox02Client.verifyCompactSignature(zeroScalar));

            byte[] outOfRange = signature.clone();
            System.arraycopy(curveOrder, 0, outOfRange, offset, 32);
            assertThrows(DeviceException.class, () -> BitBox02Client.verifyCompactSignature(outOfRange));
        }
    }

    @Test
    public void testRecoverableSignature() {
        byte[] signature = Arrays.copyOf(Utils.hexToBytes(LOW_S), 65);
        assertThrows(DeviceException.class, () -> BitBox02Client.verifyRecoverableSignature(Arrays.copyOfRange(signature, 0, 64)));

        for(byte recoveryId = 0; recoveryId <= 3; recoveryId++) {
            signature[64] = recoveryId;
            assertDoesNotThrow(() -> BitBox02Client.verifyRecoverableSignature(signature));
        }

        signature[64] = 4;
        assertThrows(DeviceException.class, () -> BitBox02Client.verifyRecoverableSignature(signature));

        signature[64] = (byte)0xff;
        assertThrows(DeviceException.class, () -> BitBox02Client.verifyRecoverableSignature(signature));

        byte[] highS = Arrays.copyOf(Utils.hexToBytes(HIGH_S), 65);
        assertThrows(DeviceException.class, () -> BitBox02Client.verifyRecoverableSignature(highS));
    }
}
