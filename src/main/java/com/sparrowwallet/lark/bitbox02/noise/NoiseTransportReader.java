package com.sparrowwallet.lark.bitbox02.noise;

import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;

/**
 * <p>A Noise transport reader decrypts Noise transport messages. In the terminology of the Noise
 * Protocol Framework specification, a {@code NoiseTransportReader} instance encapsulates a "cipher state" produced by
 * "splitting" a {@link NoiseHandshake} instance.</p>
 *
 * <p>Noise transport reader instances are stateful and are <em>not</em> thread-safe.</p>
 *
 * @see NoiseHandshake#toTransportReader()
 * @see NoiseHandshake#toTransport()
 */
public interface NoiseTransportReader {

  /**
   * Returns the length of the plaintext resulting from the decryption of a ciphertext of the given size.
   *
   * @param ciphertextLength the length of a ciphertext
   *
   * @return the length of the plaintext resulting from the decryption of a ciphertext of the given size
   *
   * @throws IllegalArgumentException if the given ciphertext length is too small to contain a valid AEAD tag
   */
  int getPlaintextLength(final int ciphertextLength);

  /**
   * Decrypts a Noise transport message and verifies its AEAD tag. This method returns a new {@link ByteBuffer} sized exactly
   * to contain the resulting plaintext. The returned buffer's position will be zero, and its limit and capacity will be
   * equal to the plaintext length.
   * <p>
   * All {@code ciphertext.remaining()} bytes starting at {@code ciphertext.position()} are processed. Upon return, the
   * ciphertext buffer's position will be equal to its limit; its limit will not have changed.
   *
   * @param ciphertext the ciphertext of the Noise transport message to decrypt
   *
   * @return a {@code ByteBuffer} containing the resulting plaintext
   *
   * @throws AEADBadTagException if the AEAD tag in the given ciphertext does not match the calculated value
   * @throws IllegalArgumentException if the given ciphertext is too short to contain a valid AEAD tag or if it is
   * larger than the maximum allowed Noise transport message size
   *
   * @see #getPlaintextLength(int)
   */
  ByteBuffer readMessage(final ByteBuffer ciphertext) throws AEADBadTagException;

  /**
   * Decrypts a Noise transport message and verifies its AEAD tag. This method writes the resulting plaintext into the given
   * {@code plaintext} buffer. Callers are responsible for ensuring that the given plaintext buffer has enough remaining
   * capacity to hold the resulting plaintext.
   * <p>
   * All {@code ciphertext.remaining()} bytes starting at {@code ciphertext.position()} are processed. Upon return, the
   * ciphertext buffer's position will be equal to its limit; its limit will not have changed. The plaintext buffer's
   * position will have advanced by n, where n is the value returned by this method; the plaintext buffer's limit will
   * not have changed.
   *
   * @param ciphertext the ciphertext of the Noise transport message to decrypt
   * @param plaintext the buffer into which to write the resulting plaintext
   *
   * @return the number of bytes written into the {@code plaintext} buffer
   *
   * @throws AEADBadTagException if the AEAD tag in the given ciphertext does not match the calculated value
   * @throws IllegalArgumentException if the given ciphertext is too short to contain a valid AEAD tag or if it is
   * larger than the maximum allowed Noise transport message size
   * @throws ShortBufferException if the given plaintext buffer does not have enough remaining capacity to hold the
   * resulting plaintext
   *
   * @see #getPlaintextLength(int)
   */
  int readMessage(final ByteBuffer ciphertext, final ByteBuffer plaintext) throws ShortBufferException, AEADBadTagException;

  /**
   * Decrypts a Noise transport message, returning a new byte array sized exactly to contain the resulting plaintext.
   *
   * @param ciphertext the ciphertext of the Noise transport message to decrypt
   *
   * @return a new byte array containing the resulting plaintext
   *
   * @throws AEADBadTagException if the AEAD tag in the given ciphertext does not match the calculated AEAD tag
   * @throws IllegalArgumentException if the given ciphertext is too short to contain a valid AEAD tag or if it is
   * larger than the maximum allowed Noise transport message size
   */
  byte[] readMessage(final byte[] ciphertext) throws AEADBadTagException;

  /**
   * Decrypts a Noise transport message and writes the resulting plaintext into the given byte array. Note that
   * {@code ciphertext} and {@code plaintext} may refer to the same byte array, allowing for in-place decryption.
   *
   * @param ciphertext the ciphertext of the Noise transport message to decrypt
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
   * @throws IllegalArgumentException if the given ciphertext is too short to contain a valid AEAD tag or if it is
   * larger than the maximum allowed Noise transport message size
   */
  int readMessage(final byte[] ciphertext,
                  final int ciphertextOffset,
                  final int ciphertextLength,
                  final byte[] plaintext,
                  final int plaintextOffset) throws ShortBufferException, AEADBadTagException;

  /**
   * Sets the decryption key used by this reader to a new pseudo-random key derived from the current key. This operation
   * must be coordinated with the sending party, otherwise messages from the sending party will be unintelligible and
   * decrypting future messages will fail.
   */
  void rekeyReader();
}
