package com.sparrowwallet.lark.trezor.thp.cpace;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Elligator2 mapping for Curve25519.
 *
 * Maps uniform random bytes to Curve25519 points for CPace protocol.
 * Implements RFC 9380 optimized map_to_curve_elligator2_curve25519.
 *
 * Reference: https://www.rfc-editor.org/rfc/rfc9380.html#ell2-opt
 */
public class Elligator2 {

    // Curve25519 parameters
    private static final BigInteger P = BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger J = BigInteger.valueOf(486662);  // Montgomery curve constant

    // Precomputed constants
    private static final BigInteger C3 = new BigInteger("19681161376707505956807079304988542015446066515923890162744021073123829784752");  // sqrt(-1)
    private static final BigInteger C4 = new BigInteger("7237005577332262213973186563042994240829374041602535252466099000494570602493");  // (p - 5) // 8
    private static final BigInteger P_MINUS_2 = P.subtract(BigInteger.TWO);

    /**
     * Maps a 32-byte uniform random input to a Curve25519 point.
     * Implements map_to_curve_elligator2_curve25519 from RFC 9380.
     *
     * @param input 32-byte uniform random input (typically from SHA-512 hash)
     * @return 32-byte Curve25519 point in little-endian format
     */
    public static byte[] map(byte[] input) {
        if (input == null || input.length != 32) {
            throw new IllegalArgumentException("Input must be 32 bytes");
        }

        // Decode coordinate (clear bit 7, convert to BigInteger mod p)
        BigInteger u = decodeCoordinate(input);

        // map_to_curve_elligator2_curve25519 from RFC 9380
        BigInteger tv1 = u.multiply(u).mod(P);
        tv1 = BigInteger.TWO.multiply(tv1).mod(P);
        BigInteger xd = tv1.add(BigInteger.ONE).mod(P);
        BigInteger x1n = J.negate().mod(P);
        BigInteger tv2 = xd.multiply(xd).mod(P);
        BigInteger gxd = tv2.multiply(xd).mod(P);
        BigInteger gx1 = J.multiply(tv1).mod(P);
        gx1 = gx1.multiply(x1n).mod(P);
        gx1 = gx1.add(tv2).mod(P);
        gx1 = gx1.multiply(x1n).mod(P);
        BigInteger tv3 = gxd.multiply(gxd).mod(P);
        tv2 = tv3.multiply(tv3).mod(P);
        tv3 = tv3.multiply(gxd).mod(P);
        tv3 = tv3.multiply(gx1).mod(P);
        tv2 = tv2.multiply(tv3).mod(P);
        BigInteger y11 = tv2.modPow(C4, P);
        y11 = y11.multiply(tv3).mod(P);
        BigInteger y12 = y11.multiply(C3).mod(P);
        tv2 = y11.multiply(y11).mod(P);
        tv2 = tv2.multiply(gxd).mod(P);
        boolean e1 = tv2.equals(gx1);
        BigInteger y1 = conditionalMove(y12, y11, e1);
        BigInteger x2n = x1n.multiply(tv1).mod(P);
        tv2 = y1.multiply(y1).mod(P);
        tv2 = tv2.multiply(gxd).mod(P);
        boolean e3 = tv2.equals(gx1);
        BigInteger xn = conditionalMove(x2n, x1n, e3);
        BigInteger x = xn.multiply(xd.modPow(P_MINUS_2, P)).mod(P);

        return encodeCoordinate(x);
    }

    /**
     * Decode coordinate from bytes (clear bit 7, little-endian).
     */
    private static BigInteger decodeCoordinate(byte[] coordinate) {
        byte[] copy = Arrays.copyOf(coordinate, 32);
        copy[31] &= 0x7F;  // Clear bit 7
        return new BigInteger(1, reverseBytes(copy)).mod(P);
    }

    /**
     * Encode coordinate to bytes (little-endian).
     */
    private static byte[] encodeCoordinate(BigInteger coordinate) {
        byte[] bigEndian = coordinate.toByteArray();
        byte[] result = new byte[32];

        // Handle sign byte from BigInteger
        int srcPos = 0;
        int length = bigEndian.length;
        if (bigEndian.length > 32 || (bigEndian.length == 32 && bigEndian[0] == 0)) {
            srcPos = 1;
            length--;
        }

        // Convert to little-endian
        for (int i = 0; i < length && i < 32; i++) {
            result[i] = bigEndian[srcPos + length - 1 - i];
        }

        return result;
    }

    /**
     * Constant-time conditional move.
     * Returns second if condition is true, first otherwise.
     */
    private static BigInteger conditionalMove(BigInteger first, BigInteger second, boolean condition) {
        // For non-constant-time Java implementation, just use condition
        // (In real crypto, this should be constant-time)
        return condition ? second : first;
    }

    /**
     * Reverse byte array (for endianness conversion).
     */
    private static byte[] reverseBytes(byte[] input) {
        byte[] result = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            result[i] = input[input.length - 1 - i];
        }
        return result;
    }
}
