package com.sparrowwallet.lark.bitbox02.noise.crypto;

import javax.crypto.MacSpi;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

abstract class HmacSpi extends MacSpi {

  private final MessageDigest messageDigest;
  private final int blockLength;

  private final byte[] keyBytes;

  private static final String KEY_ALGORITHM = "RAW";

  private static final byte INNER_PADDING_BYTE = 0x36;
  private static final byte OUTER_PADDING_BYTE = 0x5c;

  protected HmacSpi(final MessageDigest messageDigest, final int blockLength) {
    this.messageDigest = messageDigest;
    this.blockLength = blockLength;

    this.keyBytes = new byte[blockLength];
  }

  @Override
  protected void engineReset() {
    messageDigest.reset();
    Arrays.fill(keyBytes, (byte) 0);
  }

  @Override
  protected void engineInit(final Key key, final AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (!key.getAlgorithm().equals(KEY_ALGORITHM)) {
      throw new InvalidKeyException("HMAC only supports RAW keys");
    }

    if (params != null) {
      throw new InvalidAlgorithmParameterException("No algorithm parameters expected");
    }

    engineReset();

    final byte[] encodedKeyBytes = key.getEncoded();

    if (encodedKeyBytes.length > blockLength) {
      messageDigest.update(encodedKeyBytes);

      try {
        // Note that calling `digest` also resets the message digest
        messageDigest.digest(keyBytes, 0, blockLength);
      } catch (final DigestException e) {
        // This should never happen for a key and buffer we control
        throw new AssertionError(e);
      }
    } else {
      System.arraycopy(encodedKeyBytes, 0, keyBytes, 0, encodedKeyBytes.length);
    }

    for (final byte b : keyBytes) {
      messageDigest.update((byte) (b ^ INNER_PADDING_BYTE));
    }
  }

  @Override
  protected void engineUpdate(final byte input) {
    messageDigest.update(input);
  }

  @Override
  protected void engineUpdate(final byte[] input, final int offset, final int len) {
    messageDigest.update(input, offset, len);
  }

  @Override
  protected byte[] engineDoFinal() {
    final byte[] innerHash = messageDigest.digest();

    messageDigest.reset();

    for (final byte b : keyBytes) {
      messageDigest.update((byte) (b ^ OUTER_PADDING_BYTE));
    }

    try {
      return messageDigest.digest(innerHash);
    } finally {
      engineReset();
    }
  }
}
