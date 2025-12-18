package com.sparrowwallet.lark.noise.component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * A Noise hash implementation encapsulates the hashing functionality of a Noise protocol. A Noise hash provides
 * {@link MessageDigest} instances that implement the Noise hash's hashing algorithm, {@link Mac} instances using the
 * same algorithm for calculating HMAC digests, and key derivation function.
 */
public interface NoiseHash {

  /**
   * <p>Returns a {@code NoiseHash} instance that implements the named hash algorithm. This method recognizes the
   * following hash names:</p>
   *
   * <dl>
   *   <dt>SHA256</dt>
   *   <dd>Returns a Noise hash implementation backed by the {@link MessageDigest} returned by the most
   *   preferred security provider that supports the "SHA-256" algorithm and the {@link Mac} returned by
   *   the most preferred security provider that supports the "HmacSHA256" algorithm</dd>
   *
   *   <dt>SHA512</dt>
   *   <dd>Returns a Noise hash implementation backed by the {@link MessageDigest} returned by the most
   *   preferred security provider that supports the "SHA-512" algorithm and the {@link Mac} returned by
   *   the most preferred security provider that supports the "HmacSHA512" algorithm</dd>
   *
   *   <dt>BLAKE2s</dt>
   *   <dd>Returns a Noise hash implementation backed by BLAKE2s implementations included in java-noise</dd>
   *
   *   <dt>BLAKE2b</dt>
   *   <dd>Returns a Noise hash implementation backed by BLAKE2b implementations included in java-noise</dd>
   * </dl>
   *
   * <p>Every implementation of the Java platform is required to support the "SHA-256" and "HmacSHA256" algorithms.
   * Java-noise provides its own BLAKE2b/BLAKE2s implementations.</p>
   *
   * @param noiseHashName the name of the Noise hash algorithm for which to return a concrete {@code NoiseHash}
   *                      implementation
   *
   * @return a concrete {@code NoiseCipher} implementation for the given algorithm name
   *
   * @throws NoSuchAlgorithmException if the given name is "SHA512" and either the "SHA-512" or "HmacSHA512" algorithm
   * is not supported by any security provider in the current JVM
   * @throws IllegalArgumentException if the given name is not a known Noise hash name
   *
   * @see MessageDigest#getInstance(String)
   * @see Mac#getInstance(String)
   */
  static NoiseHash getInstance(final String noiseHashName) throws NoSuchAlgorithmException {
    return switch (noiseHashName) {
      case "SHA256" -> new Sha256NoiseHash();
      case "SHA512" -> new Sha512NoiseHash();
      case "BLAKE2s" -> new Blake2sNoiseHash();
      case "BLAKE2b" -> new Blake2bNoiseHash();
      default -> throw new IllegalArgumentException("Unrecognized hash name: " + noiseHashName);
    };
  }

  /**
   * Returns the name of this Noise hash as it would appear in a full Noise protocol name.
   *
   * @return the name of this Noise hash as it would appear in a full Noise protocol name
   */
  String getName();

  /**
   * Returns a new {@link MessageDigest} for calculating hashes using this Noise hash's hashing algorithm.
   *
   * @return a new {@link MessageDigest} for calculating hashes
   */
  MessageDigest getMessageDigest();

  /**
   * Returns a new {@link Mac} instance for calculating HMAC digests using this Noise hash's hashing algorithm.
   *
   * @return a new {@code Mac} instance for calculating HMAC digests
   */
  Mac getHmac();

  /**
   * Returns the length of a digest produced by the {@link MessageDigest} or {@link Mac} provided by this Noise hash.
   *
   * @return the length of a digest produced by this Noise hash
   */
  int getHashLength();

  /**
   * <p>Derives two or three pseudo-random keys from the given chaining key and input key material using the HKDF
   * algorithm with this Noise hash's HMAC algorithm.</p>
   *
   * <p>As the Noise Protocol Framework specification notes:</p>
   *
   * <blockquote>Note that [the derived keys] are all [{@link #getHashLength()}] bytes in length. Also note that the
   * [{@code deriveKeys}] function is simply HKDF from [IETF RFC 5869] with the chaining_key as HKDF salt, and
   * zero-length HKDF info.</blockquote>
   *
   * @param chainingKey the chaining key (salt) from which to derive new keys
   * @param inputKeyMaterial the input key material from which to derive new keys
   * @param outputKeys the number of keys to derive; must be either 2 or 3
   *
   * @return an array containing {@code outputKeys} derived keys
   *
   * @see <a href="https://www.ietf.org/rfc/rfc5869.txt">IETF RFC 5869: HMAC-based Extract-and-Expand Key Derivation
   * Function (HKDF)</a>
   */
  default byte[][] deriveKeys(final byte[] chainingKey, final byte[] inputKeyMaterial, final int outputKeys) {
    if (outputKeys < 2 || outputKeys > 3) {
      throw new IllegalArgumentException("Illegal output key count");
    }

    final byte[][] derivedKeys = new byte[getHashLength()][outputKeys];

    final Mac hmac = getHmac();

    try {
      hmac.init(new SecretKeySpec(chainingKey, "RAW"));
      final Key tempKey = new SecretKeySpec(hmac.doFinal(inputKeyMaterial), "RAW");

      for (byte k = 0; k < outputKeys; k++) {
        hmac.init(tempKey);

        if (k > 0) {
          hmac.update(derivedKeys[k - 1]);
        }

        hmac.update((byte) (k + 1));
        derivedKeys[k] = hmac.doFinal();
      }

      return derivedKeys;
    } catch (final InvalidKeyException e) {
      // This should never happen for keys we derive/control
      throw new AssertionError(e);
    }
  }
}
