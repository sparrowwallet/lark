package com.sparrowwallet.lark.bitbox02.noise;

import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;

/**
 * <p>A Noise transport writer encrypts Noise transport messages. In the terminology of the Noise Protocol Framework
 * specification, a {@code NoiseTransportWriter} instance encapsulates a "cipher state" produced by "splitting" a
 * {@link NoiseHandshake} instance.</p>
 *
 * <p>Noise transport writer instances are stateful and are <em>not</em> thread-safe.</p>
 *
 * @see NoiseHandshake#toTransportWriter()
 * @see NoiseHandshake#toTransport()
 */
public interface NoiseTransportWriter {

  /**
   * Returns the length of the ciphertext resulting from the encryption of a plaintext of the given length.
   *
   * @param plaintextLength the length of a plaintext
   *
   * @return the length of the ciphertext resulting from the encryption of a plaintext of the given size
   */
  int getCiphertextLength(final int plaintextLength);

  /**
   * Encrypts a Noise transport message, returning a new byte buffer sized exactly to contain the resulting ciphertext.
   * <p>
   * All {@code plaintext.remaining()} bytes starting at {@code plaintext.position()} are processed. Upon return, the
   * plaintext buffer's position will be equal to its limit; its limit will not have changed. The returned ciphertext
   * buffer's position will be zero, and its limit will be equal to its capacity.
   *
   * @param plaintext the plaintext to encrypt
   *
   * @return a new byte buffer containing the resulting ciphertext and AEAD tag
   *
   * @throws IllegalArgumentException if the ciphertext for the given plaintext would be larger than the maximum allowed
   * Noise transport message size
   *
   * @see #getCiphertextLength(int)
   */
  ByteBuffer writeMessage(final ByteBuffer plaintext);

  /**
   * Encrypts a Noise transport message. Callers are responsible for ensuring that the given ciphertext buffer has
   * enough remaining capacity to hold the resulting ciphertext and AEAD tag.
   * <p>
   * All {@code plaintext.remaining()} bytes starting at {@code plaintext.position()} are processed. Upon return, the
   * plaintext buffer's position will be equal to its limit; its limit will not have changed. The ciphertext buffer's
   * position will have advanced by n, where n is the value returned by this method; the ciphertext buffer's limit will
   * not have changed.
   * <p>
   * Note that the ciphertext and plaintext buffers must be different, but may refer to the same underlying byte array
   * to facilitate in-place encryption.
   *
   * @param plaintext the plaintext to encrypt
   * @param ciphertext the buffer into which to write the resulting ciphertext and AEAD tag
   *
   * @return the number of bytes written into the ciphertext buffer
   *
   * @throws IllegalArgumentException if the ciphertext for the given plaintext would be larger than the maximum allowed
   * Noise transport message size
   * @throws ShortBufferException if the given ciphertext buffer does not have enough remaining capacity to hold the
   * resulting ciphertext and AEAD tag
   *
   * @see #getCiphertextLength(int)
   */
  int writeMessage(final ByteBuffer plaintext, final ByteBuffer ciphertext) throws ShortBufferException;

  /**
   * Encrypts a Noise transport message, returning a byte array sized exactly to contain the resulting ciphertext.
   *
   * @param plaintext the plaintext to encrypt
   *
   * @return a new byte array containing the resulting ciphertext
   *
   * @throws IllegalArgumentException if the ciphertext for the given plaintext would be larger than the maximum allowed
   * Noise transport message size
   */
  byte[] writeMessage(final byte[] plaintext);

  /**
   * Encrypts a Noise transport message. Callers are responsible for ensuring that the given ciphertext array is large
   * enough to hold the resulting ciphertext and AEAD tag.
   * <p>
   * Note that the ciphertext and plaintext arrays may refer to the same array, allowing for in-place encryption.
   *
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
   * @throws IllegalArgumentException if the ciphertext for the given plaintext would be larger than the maximum allowed
   * Noise transport message size
   *
   * @see #getCiphertextLength(int)
   */
  int writeMessage(final byte[] plaintext,
                   final int plaintextOffset,
                   final int plaintextLength,
                   final byte[] ciphertext,
                   final int ciphertextOffset) throws ShortBufferException;

  /**
   * Sets the encryption key used by this writer to a new pseudo-random key derived from the current key. This operation
   * must be coordinated with the receiving party, otherwise messages sent to the receiving party will be unintelligible
   * and decrypting future messages will fail.
   */
  void rekeyWriter();
}
