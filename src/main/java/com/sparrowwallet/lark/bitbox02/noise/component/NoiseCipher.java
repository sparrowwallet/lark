package com.sparrowwallet.lark.bitbox02.noise.component;

import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * A Noise cipher is a stateless object that encrypts and decrypts data for use in a Noise protocol. Noise cipher
 * implementations must operate in AEAD mode, produce a 16-byte AEAD tag when encrypting data, and verify a 16-byte
 * AEAD tag when decrypting data.
 */
public interface NoiseCipher {

  /**
   * <p>Returns a {@code NoiseCipher} instance that implements the named cipher algorithm. This method recognizes the
   * following cipher names:</p>
   *
   * <dl>
   *   <dt>ChaChaPoly</dt>
   *   <dd>Returns a Noise cipher implementation backed by the {@link javax.crypto.Cipher} returned by the most
   *   preferred security provider that supports the "ChaCha20-Poly1305" cipher transformation</dd>
   *
   *   <dt>AESGCM</dt>
   *   <dd>Returns a Noise cipher implementation backed by the {@link javax.crypto.Cipher} returned by the most
   *   preferred security provider that supports the "AES/GCM/NoPadding" cipher transformation</dd>
   * </dl>
   *
   * <p>Every implementation of the Java platform is required to support the "AES/GCM/NoPadding" cipher transformation,
   * which underpins the "AESGCM" Noise cipher.</p>
   *
   * @param noiseCipherName the name of the Noise cipher algorithm for which to return a concrete {@code NoiseCipher}
   *                        implementation
   *
   * @return a concrete {@code NoiseCipher} implementation for the given algorithm name
   *
   * @throws NoSuchAlgorithmException if the given name is "ChaChaPoly" and the "ChaCha20-Poly1305" cipher
   * transformation is not supported by any security provider in the current JVM
   * @throws IllegalArgumentException if the given name is not a known Noise cipher name
   *
   * @see javax.crypto.Cipher#getInstance(String)
   */
  static NoiseCipher getInstance(final String noiseCipherName) throws NoSuchAlgorithmException {
    return switch (noiseCipherName) {
      case "ChaChaPoly" -> new ChaCha20Poly1305Cipher();
      case "AESGCM" -> new AesGcmCipher();
      default -> throw new IllegalArgumentException("Unrecognized Noise cipher name: " + noiseCipherName);
    };
  }

  /**
   * Returns the name of this Noise cipher as it would appear in a full Noise protocol name.
   *
   * @return the name of this Noise cipher as it would appear in a full Noise protocol name
   */
  String getName();

  /**
   * <p>Encrypts the given plaintext using the given key, nonce, and associated data. This method returns a new byte
   * buffer sized exactly to contain the resulting ciphertext and AEAD tag.</p>
   *
   * <p>All {@code plaintext.remaining()} bytes starting at {@code plaintext.position()} are processed. Upon return, the
   * plaintext buffer's position will be equal to its limit; its limit will not have changed. If associated data is
   * provided, the same is true of the associated data buffer. The returned ciphertext buffer's position will be zero,
   * and its limit will be equal to its capacity.</p>
   *
   * @param key the key with which to encrypt the given plaintext
   * @param nonce a nonce, which must be unique for the given key
   * @param associatedData the associated data to use when calculating an AEAD tag
   * @param plaintext the plaintext to encrypt
   *
   * @return a new byte buffer containing the resulting ciphertext and AEAD tag
   * 
   * @see #getCiphertextLength(int) 
   */
  default ByteBuffer encrypt(final Key key,
                             final long nonce,
                             final byte[] associatedData,
                             final ByteBuffer plaintext) {

    final ByteBuffer ciphertext = ByteBuffer.allocate(getCiphertextLength(plaintext.remaining()));

    try {
      encrypt(key, nonce, associatedData, plaintext, ciphertext);
      ciphertext.flip();
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return ciphertext;
  }

  /**
   * <p>Encrypts the given plaintext using the given key, nonce, and associated data. Callers are responsible for
   * ensuring that the given ciphertext buffer has enough remaining capacity to hold the resulting ciphertext and AEAD
   * tag.</p>
   *
   * <p>All {@code plaintext.remaining()} bytes starting at {@code plaintext.position()} are processed. Upon return, the
   * plaintext buffer's position will be equal to its limit; its limit will not have changed. If associated data is
   * provided, the same will be true of the associated data buffer. The ciphertext buffer's position will have advanced
   * by n, where n is the value returned by this method; the ciphertext buffer's limit will not have changed.</p>
   *
   * <p>Note that the ciphertext and plaintext buffers must be different, but may refer to the same underlying byte
   * array to facilitate in-place encryption.</p>
   *
   * @param key the key with which to encrypt the given plaintext
   * @param nonce a nonce, which must be unique for the given key
   * @param associatedData the associated data to use when calculating an AEAD tag
   * @param plaintext the plaintext to encrypt
   * @param ciphertext the buffer into which to write the resulting ciphertext and AEAD tag
   *
   * @return the number of bytes written into the ciphertext buffer
   *
   * @throws ShortBufferException if the given ciphertext buffer does not have enough remaining capacity to hold the
   * resulting ciphertext and AEAD tag
   *
   * @see #getCiphertextLength(int)
   */
  int encrypt(final Key key,
              final long nonce,
              final byte[] associatedData,
              final ByteBuffer plaintext,
              final ByteBuffer ciphertext)
      throws ShortBufferException;

  /**
   * Encrypts the given plaintext using the given key, nonce, and associated data. This method returns a new byte array
   * sized exactly to contain the resulting ciphertext and AEAD tag.
   *
   * @param key the key with which to encrypt the given plaintext
   * @param nonce a nonce, which must be unique for the given key
   * @param associatedData the associated data to use when calculating an AEAD tag
   * @param plaintext the plaintext to encrypt
   *
   * @return a new byte array containing the resulting ciphertext and AEAD tag
   *
   * @see #getCiphertextLength(int)
   */
  default byte[] encrypt(final Key key,
                         final long nonce,
                         final byte[] associatedData,
                         final byte[] plaintext) {

    final byte[] ciphertext = new byte[getCiphertextLength(plaintext.length)];

    try {
      encrypt(key,
          nonce,
          associatedData,
          plaintext,
          0,
          plaintext.length,
          ciphertext,
          0);
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return ciphertext;
  }

  /**
   * <p>Encrypts the given plaintext using the given key, nonce, and associated data. Callers are responsible for
   * ensuring that the given ciphertext array is large enough to hold the resulting ciphertext and AEAD tag.</p>
   *
   * <p>Note that the ciphertext and plaintext arrays may refer to the same array, allowing for in-place encryption.</p>
   *
   * @param key the key with which to encrypt the given plaintext
   * @param nonce a nonce, which must be unique for the given key
   * @param associatedData a byte array containing the associated data (if any) to be used when encrypting the given
   *                       plaintext; may be {@code null}
   * @param plaintext a byte array containing the plaintext to encrypt
   * @param plaintextOffset the offset within {@code plaintext} where the plaintext begins
   * @param plaintextLength the length of the plaintext within {@code plaintext}
   * @param ciphertext a byte array into which to write the ciphertext and AEAD tag from this encryption operation
   * @param ciphertextOffset the position within {@code ciphertext} at which to begin writing the ciphertext and AEAD
   *                         tag
   *
   * @return the number of bytes written into the ciphertext array
   *
   * @throws ShortBufferException if the ciphertext array (after its offset) is too small to hold the resulting
   * ciphertext and AEAD tag
   * @throws IndexOutOfBoundsException if the given plaintext length exceeds the length of the plaintext array after its
   * offset
   *
   * @see #getCiphertextLength(int)
   */
  int encrypt(final Key key,
              final long nonce,
              final byte[] associatedData,
              final byte[] plaintext,
              final int plaintextOffset,
              final int plaintextLength,
              final byte[] ciphertext,
              final int ciphertextOffset) throws ShortBufferException;

  /**
   * <p>Decrypts the given ciphertext and verifies its AEAD tag using the given key, nonce, and associated data. This
   * method returns a new {@link ByteBuffer} sized exactly to contain the resulting plaintext. The returned buffer's
   * position will be zero, and its limit and capacity will be equal to the plaintext length.</p>
   *
   * <p>All {@code ciphertext.remaining()} bytes starting at {@code ciphertext.position()} are processed. Upon return,
   * the ciphertext buffer's position will be equal to its limit; its limit will not have changed. If associated data is
   * provided, the same will be true of the associated data buffer.</p>
   *
   * @param key the key with which to decrypt the given ciphertext
   * @param nonce a nonce, which must be unique for the given key
   * @param associatedData the associated data to use when verifying the AEAD tag; may be {@code null}
   * @param ciphertext the ciphertext to decrypt
   *
   * @return a {@code ByteBuffer} containing the resulting plaintext
   *
   * @throws AEADBadTagException if the AEAD tag in the given ciphertext does not match the calculated value
   * @throws IllegalArgumentException if the given ciphertext is too short to contain a valid AEAD tag
   *
   * @see #getPlaintextLength(int)
   */
  default ByteBuffer decrypt(final Key key,
                             final long nonce,
                             final byte[] associatedData,
                             final ByteBuffer ciphertext) throws AEADBadTagException {

    final ByteBuffer plaintext = ByteBuffer.allocate(getPlaintextLength(ciphertext.remaining()));

    try {
      decrypt(key, nonce, associatedData, ciphertext, plaintext);
      plaintext.rewind();
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return plaintext;
  }

  /**
   * <p>Decrypts the given ciphertext and verifies its AEAD tag using the given key, nonce, and associated data. This
   * method writes the resulting plaintext into the given {@code plaintext} buffer. Callers are responsible for ensuring
   * that the given plaintext buffer has enough remaining capacity to hold the resulting plaintext.</p>
   *
   * <p>All {@code ciphertext.remaining()} bytes starting at {@code ciphertext.position()} are processed. Upon return,
   * the ciphertext buffer's position will be equal to its limit; its limit will not have changed. If associated data is
   * provided, the same will be true of the associated data buffer. The plaintext buffer's position will have advanced
   * by n, where n is the value returned by this method; the plaintext buffer's limit will not have changed.</p>
   *
   * @param key the key with which to decrypt the given ciphertext
   * @param nonce a nonce, which must be unique for the given key
   * @param associatedData the associated data to use when verifying the AEAD tag; may be {@code null}
   * @param ciphertext the ciphertext to decrypt
   * @param plaintext the buffer into which to write the resulting plaintext
   *
   * @return the number of bytes written into the {@code plaintext} buffer
   *
   * @throws AEADBadTagException if the AEAD tag in the given ciphertext does not match the calculated value
   * @throws IllegalArgumentException if the given ciphertext is too short to contain a valid AEAD tag
   * @throws ShortBufferException if the given plaintext buffer does not have enough remaining capacity to hold the
   * resulting plaintext
   *
   * @see #getPlaintextLength(int)
   */
  int decrypt(final Key key,
              final long nonce,
              final byte[] associatedData,
              final ByteBuffer ciphertext,
              final ByteBuffer plaintext)
      throws AEADBadTagException, ShortBufferException;

  /**
   * Decrypts the given ciphertext and verifies its AEAD tag using the given key, nonce, and associated data. This
   * method returns a new byte array sized exactly to contain the resulting plaintext.
   *
   * @param key the key with which to decrypt the given ciphertext
   * @param nonce a nonce, which must be unique for the given key
   * @param associatedData the associated data to use when verifying the AEAD tag; may be {@code null}
   * @param ciphertext the ciphertext to decrypt
   *
   * @return a byte array containing the resulting plaintext
   *
   * @throws AEADBadTagException if the AEAD tag in the given ciphertext does not match the calculated value
   * @throws IllegalArgumentException if the given ciphertext is too short to contain a valid AEAD tag
   * 
   * @see #getPlaintextLength(int) 
   */
  default byte[] decrypt(final Key key,
                         final long nonce,
                         final byte[] associatedData,
                         final byte[] ciphertext) throws AEADBadTagException {

    final byte[] plaintext = new byte[getPlaintextLength(ciphertext.length)];

    try {
      decrypt(key,
          nonce,
          associatedData,
          ciphertext,
          0,
          ciphertext.length,
          plaintext,
          0);
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return plaintext;
  }

  /**
   * <p>Decrypts the given ciphertext and verifies its AEAD tag. This writes the resulting plaintext into a provided
   * byte array.</p>
   *
   * <p>Note that {@code ciphertext} and {@code plaintext} may refer to the same byte array, allowing for in-place
   * decryption.</p>
   *
   * @param key the key with which to decrypt the given plaintext
   * @param nonce a nonce, which must be unique for the given key
   * @param associatedData a byte array containing the associated data (if any) to be used when verifying the AEAD tag
   *                       for the given ciphertext; may be {@code null}
   * @param ciphertext a byte array containing the ciphertext and AEAD tag to be decrypted and verified
   * @param ciphertextOffset the position within {@code ciphertext} at which to begin reading the ciphertext and AEAD
   *                         tag
   * @param ciphertextLength the length of the ciphertext and AEAD tag within {@code ciphertext}
   * @param plaintext a byte array into which to write the decrypted plaintext
   * @param plaintextOffset the offset within {@code plaintext} where the plaintext begins
   *
   * @return the number of bytes written to {@code plaintext}
   *
   * @throws AEADBadTagException if the AEAD tag in the given ciphertext does not match the calculated value
   * @throws ShortBufferException if {@code plaintext} is not long enough (after its offset) to contain the resulting
   * plaintext
   * @throws IllegalArgumentException if the given ciphertext is too short to contain a valid AEAD tag
   *
   * @see #getPlaintextLength(int)
   */
  int decrypt(final Key key,
              final long nonce,
              final byte[] associatedData,
              final byte[] ciphertext,
              final int ciphertextOffset,
              final int ciphertextLength,
              final byte[] plaintext,
              final int plaintextOffset) throws AEADBadTagException, ShortBufferException;

  /**
   * Returns the size of a buffer needed to hold the ciphertext produced by encrypting a plaintext of the given length
   * (the length of the plaintext plus the length of an AEAD tag).
   *
   * @param plaintextLength the length of a plaintext
   *
   * @return the length of the ciphertext that would be produced by encrypting a plaintext of the given length
   */
  default int getCiphertextLength(final int plaintextLength) {
    return plaintextLength + 16;
  }

  /**
   * Returns the size of a buffer needed to hold the plaintext produced by decrypting a ciphertext of the given length
   * (the length of the ciphertext minus the length of the AEAD tag).
   *
   * @param ciphertextLength the length of a ciphertext
   *
   * @return the length of the plaintext that would be produced by decrypting a ciphertext of the given length
   */
  default int getPlaintextLength(final int ciphertextLength) {
    if (ciphertextLength < 16) {
      throw new IllegalArgumentException("Ciphertexts must be at least 16 bytes long");
    }

    return ciphertextLength - 16;
  }

  /**
   * Converts an array of bytes into a {@link Key} instance suitable for use with this cipher.
   *
   * @param keyBytes the raw bytes of the key
   *
   * @return a {@code Key} suitable for use with this cipher
   */
  Key buildKey(byte[] keyBytes);

  /**
   * Generates a new pseudo-random key as a function of the given key.
   *
   * @param key the key from which to derive a new key
   *
   * @return a new pseudo-random key derived from the given key
   */
  default Key rekey(final Key key) {
    return buildKey(encrypt(key, 0xffffffffffffffffL, null, new byte[32]));
  }
}
