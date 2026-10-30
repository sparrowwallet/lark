package com.sparrowwallet.lark.yubikey;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class YubiKeyHmacProviderTest {
    private static final int FRAME_SIZE = 70;
    private static final int SHA1_MAX_BLOCK_SIZE = 64;
    private static final byte SLOT_CHAL_HMAC2 = 0x38;
    private static final int CRC_OK_RESIDUAL = 0xF0B8;

    @Test
    public void crc16MatchesCrc16X25CheckValue() {
        byte[] check = "123456789".getBytes(StandardCharsets.US_ASCII);
        int crc = YubiKeyHmacProvider.crc16(check, check.length);

        //CRC-16/X-25 is this same polynomial and init with a final complement, and its published check value is 0x906E
        Assertions.assertEquals(0x906E, crc ^ 0xFFFF);
        Assertions.assertEquals(0x6F91, crc);
    }

    @Test
    public void crc16OfEmptyInputIsInitialValue() {
        Assertions.assertEquals(0xFFFF, YubiKeyHmacProvider.crc16(new byte[0], 0));
    }

    @Test
    public void appendingComplementedCrcYieldsTheOkResidual() {
        //This is the convention the device uses for responses, and what the response check relies on
        byte[] payload = new byte[20];
        for(int i = 0; i < payload.length; i++) {
            payload[i] = (byte)(i * 7 + 3);
        }

        int crc = YubiKeyHmacProvider.crc16(payload, payload.length) ^ 0xFFFF;
        byte[] framed = Arrays.copyOf(payload, payload.length + 2);
        framed[payload.length] = (byte)(crc & 0xFF);
        framed[payload.length + 1] = (byte)((crc >> 8) & 0xFF);

        Assertions.assertEquals(CRC_OK_RESIDUAL, YubiKeyHmacProvider.crc16(framed, framed.length));
    }

    @Test
    public void corruptedResponseFailsTheResidualCheck() {
        byte[] payload = new byte[20];
        Arrays.fill(payload, (byte)0x5a);

        int crc = YubiKeyHmacProvider.crc16(payload, payload.length) ^ 0xFFFF;
        byte[] framed = Arrays.copyOf(payload, payload.length + 2);
        framed[payload.length] = (byte)(crc & 0xFF);
        framed[payload.length + 1] = (byte)((crc >> 8) & 0xFF);

        framed[0] ^= 0x01;

        Assertions.assertNotEquals(CRC_OK_RESIDUAL, YubiKeyHmacProvider.crc16(framed, framed.length));
    }

    @Test
    public void challengeFrameLayout() {
        byte[] challenge = new byte[16];
        for(int i = 0; i < challenge.length; i++) {
            challenge[i] = (byte)i;
        }

        byte[] frame = new YubiKeyHmacProvider().buildChallengeFrame(challenge);

        Assertions.assertEquals(FRAME_SIZE, frame.length);
        Assertions.assertArrayEquals(challenge, Arrays.copyOfRange(frame, 0, challenge.length));
        //Padded to the full block with a byte differing from the last challenge byte, as ykman does
        byte[] expectedPadding = new byte[SHA1_MAX_BLOCK_SIZE - challenge.length];
        Assertions.assertArrayEquals(expectedPadding, Arrays.copyOfRange(frame, challenge.length, SHA1_MAX_BLOCK_SIZE));
        Assertions.assertEquals(SLOT_CHAL_HMAC2, frame[SHA1_MAX_BLOCK_SIZE]);

        int crc = YubiKeyHmacProvider.crc16(frame, SHA1_MAX_BLOCK_SIZE);
        Assertions.assertEquals((byte)(crc & 0xFF), frame[SHA1_MAX_BLOCK_SIZE + 1]);
        Assertions.assertEquals((byte)((crc >> 8) & 0xFF), frame[SHA1_MAX_BLOCK_SIZE + 2]);
        //Trailing filler stays zero
        Assertions.assertArrayEquals(new byte[3], Arrays.copyOfRange(frame, SHA1_MAX_BLOCK_SIZE + 3, FRAME_SIZE));
    }

    @Test
    public void challengeLongerThanTheBlockIsTruncated() {
        byte[] challenge = new byte[100];
        Arrays.fill(challenge, (byte)0x41);

        byte[] frame = new YubiKeyHmacProvider().buildChallengeFrame(challenge);

        Assertions.assertEquals(FRAME_SIZE, frame.length);
        Assertions.assertEquals(SLOT_CHAL_HMAC2, frame[SHA1_MAX_BLOCK_SIZE]);
        for(int i = 0; i < SHA1_MAX_BLOCK_SIZE; i++) {
            Assertions.assertEquals((byte)0x41, frame[i]);
        }
    }

    @Test
    public void challengeEndingInZeroIsPaddedWithOnes() {
        //Zero padding here would leave a variable length slot unable to tell where the challenge ends
        byte[] challenge = new byte[] {0x01, 0x02, 0x00};

        byte[] frame = new YubiKeyHmacProvider().buildChallengeFrame(challenge);

        byte[] expectedPadding = new byte[SHA1_MAX_BLOCK_SIZE - challenge.length];
        Arrays.fill(expectedPadding, (byte)1);
        Assertions.assertArrayEquals(expectedPadding, Arrays.copyOfRange(frame, challenge.length, SHA1_MAX_BLOCK_SIZE));
        Assertions.assertArrayEquals(challenge, Arrays.copyOfRange(frame, 0, challenge.length));
    }

    @Test
    public void challengeNotEndingInZeroIsPaddedWithZeros() {
        byte[] challenge = new byte[] {0x01, 0x02, 0x03};

        byte[] frame = new YubiKeyHmacProvider().buildChallengeFrame(challenge);

        Assertions.assertArrayEquals(new byte[SHA1_MAX_BLOCK_SIZE - challenge.length],
                Arrays.copyOfRange(frame, challenge.length, SHA1_MAX_BLOCK_SIZE));
    }

    @Test
    public void aFullBlockChallengeIsNotPadded() {
        byte[] challenge = new byte[SHA1_MAX_BLOCK_SIZE];
        Arrays.fill(challenge, (byte)0x00);

        byte[] frame = new YubiKeyHmacProvider().buildChallengeFrame(challenge);

        Assertions.assertArrayEquals(challenge, Arrays.copyOfRange(frame, 0, SHA1_MAX_BLOCK_SIZE));
        Assertions.assertEquals(SLOT_CHAL_HMAC2, frame[SHA1_MAX_BLOCK_SIZE]);
    }

    @Test
    public void differentChallengesProduceDifferentFrames() {
        byte[] first = new YubiKeyHmacProvider().buildChallengeFrame(new byte[] {1, 2, 3});
        byte[] second = new YubiKeyHmacProvider().buildChallengeFrame(new byte[] {1, 2, 4});

        Assertions.assertFalse(Arrays.equals(first, second));
    }
}
