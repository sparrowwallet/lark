package com.sparrowwallet.lark.trezor.thp.cpace;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Elligator2 mapping for Curve25519.
 *
 * Maps uniform random bytes to Curve25519 points for CPace protocol.
 * Based on draft-irtf-cfrg-hash-to-curve and Trezor firmware implementation.
 *
 * Reference: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve
 */
public class Elligator2 {

    // Curve25519 parameters
    private static final BigInteger P = BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger A = BigInteger.valueOf(486662);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    // Precomputed constants
    private static final BigInteger P_MINUS_2 = P.subtract(TWO);
    private static final BigInteger A_MINUS_2_DIV_4 = A.subtract(TWO).divide(BigInteger.valueOf(4));

    /**
     * Maps a 32-byte uniform random input to a Curve25519 point.
     *
     * @param input 32-byte uniform random input (typically from SHA-512 hash)
     * @return 32-byte Curve25519 point in little-endian format
     */
    public static byte[] map(byte[] input) {
        if (input == null || input.length != 32) {
            throw new IllegalArgumentException("Input must be 32 bytes");
        }

        // Convert input to field element (little-endian)
        byte[] inputCopy = Arrays.copyOf(input, 32);
        // Clear high bit and second-highest bit to ensure value is in field
        inputCopy[31] &= 0x3f;

        BigInteger r = new BigInteger(1, reverseBytes(inputCopy));
        r = r.mod(P);

        // Elligator2 mapping
        BigInteger rSquared = r.multiply(r).mod(P);

        // u = -A / (1 + 2*r^2)
        BigInteger denominator = BigInteger.ONE.add(TWO.multiply(rSquared)).mod(P);
        BigInteger denominatorInv = denominator.modPow(P_MINUS_2, P); // Fermat's little theorem for inversion
        BigInteger u = A.negate().multiply(denominatorInv).mod(P);

        // v^2 = u^3 + A*u^2 + u
        BigInteger uSquared = u.multiply(u).mod(P);
        BigInteger uCubed = uSquared.multiply(u).mod(P);
        BigInteger vSquared = uCubed.add(A.multiply(uSquared)).add(u).mod(P);

        // Check if v^2 is a quadratic residue
        BigInteger legendreSymbol = vSquared.modPow(P.subtract(BigInteger.ONE).divide(TWO), P);
        boolean isQR = legendreSymbol.equals(BigInteger.ONE);

        BigInteger x;
        if (isQR) {
            x = u;
        } else {
            // x = -A - u
            x = A.negate().subtract(u).mod(P);
        }

        // Ensure x is positive
        if (x.compareTo(BigInteger.ZERO) < 0) {
            x = x.add(P);
        }

        // Convert to 32-byte little-endian array
        byte[] result = new byte[32];
        byte[] xBytes = x.toByteArray();

        // Handle BigInteger's sign byte and convert to little-endian
        int srcPos = 0;
        int length = xBytes.length;

        // Skip sign byte if present
        if (xBytes.length > 32 || (xBytes.length == 32 && xBytes[0] == 0)) {
            srcPos = 1;
            length--;
        }

        // Copy and reverse to little-endian
        for (int i = 0; i < length && i < 32; i++) {
            result[i] = xBytes[srcPos + length - 1 - i];
        }

        return result;
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
