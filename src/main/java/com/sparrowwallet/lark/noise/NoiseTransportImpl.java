package com.sparrowwallet.lark.noise;

import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;

class NoiseTransportImpl implements NoiseTransport {

  private final CipherState readerState;
  private final CipherState writerState;

  static final int MAX_NOISE_MESSAGE_SIZE = 65_535;

  NoiseTransportImpl(final CipherState readerState, final CipherState writerState) {
    this.readerState = readerState;
    this.writerState = writerState;
  }

  @Override
  public int getPlaintextLength(final int ciphertextLength) {
    return readerState.getPlaintextLength(ciphertextLength);
  }

  @Override
  public int getCiphertextLength(final int plaintextLength) {
    return writerState.getCiphertextLength(plaintextLength);
  }

  @Override
  public ByteBuffer readMessage(final ByteBuffer ciphertext) throws AEADBadTagException {
    checkInboundMessageSize(ciphertext.remaining());

    return readerState.decrypt(null, ciphertext);
  }

  @Override
  public int readMessage(final ByteBuffer ciphertext, final ByteBuffer plaintext) throws ShortBufferException, AEADBadTagException {
    checkInboundMessageSize(ciphertext.remaining());

    if (plaintext.remaining() < getPlaintextLength(ciphertext.remaining())) {
      throw new ShortBufferException("Plaintext buffer does not have enough remaining capacity to hold plaintext");
    }

    return readerState.decrypt(null, ciphertext, plaintext);
  }

  @Override
  public byte[] readMessage(final byte[] ciphertext) throws AEADBadTagException {
    checkInboundMessageSize(ciphertext.length);

    return readerState.decrypt(null, ciphertext);
  }

  @Override
  public int readMessage(final byte[] ciphertext,
                         final int ciphertextOffset,
                         final int ciphertextLength,
                         final byte[] plaintext,
                         final int plaintextOffset) throws ShortBufferException, AEADBadTagException {

    checkInboundMessageSize(ciphertextLength);

    if (plaintext.length - plaintextOffset < getPlaintextLength(ciphertextLength)) {
      throw new ShortBufferException("Plaintext array after offset is not large enough to hold plaintext");
    }

    return readerState.decrypt(null,
        ciphertext, ciphertextOffset, ciphertextLength,
        plaintext, plaintextOffset);
  }

  private void checkInboundMessageSize(final int ciphertextLength) {
    if (ciphertextLength > MAX_NOISE_MESSAGE_SIZE) {
      throw new IllegalArgumentException("Message is larger than maximum allowed Noise transport message size");
    }
  }

  @Override
  public ByteBuffer writeMessage(final ByteBuffer plaintext) {
    checkOutboundMessageSize(plaintext.remaining());

    return writerState.encrypt(null, plaintext);
  }

  @Override
  public int writeMessage(final ByteBuffer plaintext, final ByteBuffer ciphertext) throws ShortBufferException {
    checkOutboundMessageSize(plaintext.remaining());

    if (ciphertext.remaining() < getCiphertextLength(plaintext.remaining())) {
      throw new ShortBufferException("Ciphertext buffer does not have enough remaining capacity to hold ciphertext");
    }

    return writerState.encrypt(null, plaintext, ciphertext);
  }

  @Override
  public byte[] writeMessage(final byte[] plaintext) {
    checkOutboundMessageSize(plaintext.length);

    return writerState.encrypt(null, plaintext);
  }

  @Override
  public int writeMessage(final byte[] plaintext,
                          final int plaintextOffset,
                          final int plaintextLength,
                          final byte[] ciphertext,
                          final int ciphertextOffset) throws ShortBufferException {

    checkOutboundMessageSize(plaintextLength);

    if (ciphertext.length - ciphertextOffset < getCiphertextLength(plaintextLength)) {
      throw new ShortBufferException("Ciphertext array after offset is not large enough to hold ciphertext");
    }

    return writerState.encrypt(null,
        plaintext, plaintextOffset, plaintextLength,
        ciphertext, ciphertextOffset);
  }

  void checkOutboundMessageSize(final int plaintextLength) {
    if (getCiphertextLength(plaintextLength) > MAX_NOISE_MESSAGE_SIZE) {
      throw new IllegalArgumentException("Ciphertext would be larger than maximum allowed Noise transport message size");
    }
  }

  @Override
  public void rekeyReader() {
    readerState.rekey();
  }

  @Override
  public void rekeyWriter() {
    writerState.rekey();
  }
}
