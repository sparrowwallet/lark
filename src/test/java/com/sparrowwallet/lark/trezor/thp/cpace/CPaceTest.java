package com.sparrowwallet.lark.trezor.thp.cpace;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Locale;

public class CPaceTest {
    @Test
    public void testDeriveCodeIgnoresDefaultLocale() {
        byte[] secret = new byte[16];
        byte[] handshakeHash = new byte[32];
        byte[] challenge = new byte[16];
        Arrays.fill(secret, (byte)1);
        Arrays.fill(handshakeHash, (byte)2);
        Arrays.fill(challenge, (byte)3);

        String code = CPace.deriveCode(secret, handshakeHash, challenge);
        Locale defaultLocale = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("fa-IR"));
            Assertions.assertEquals(code, CPace.deriveCode(secret, handshakeHash, challenge));
            Assertions.assertTrue(code.matches("[0-9]{6}"));
        } finally {
            Locale.setDefault(defaultLocale);
        }
    }
}
