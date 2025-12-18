package com.sparrowwallet.lark.noise.component;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

class ChaCha20Poly1305Cipher extends AbstractNoiseCipher {

  private static final String ALGORITHM = "ChaCha20-Poly1305";

  public ChaCha20Poly1305Cipher() throws NoSuchAlgorithmException {
    super(getCipher());
  }

  private static Cipher getCipher() {
    try {
      return Cipher.getInstance(ALGORITHM);
    } catch (final NoSuchPaddingException e) {
      // This should never happen since we're not specifying a padding
      throw new AssertionError("Padding not supported, but no padding specified", e);
    } catch (final NoSuchAlgorithmException e) {
      // This should never happen since we were able to get an instance of this cipher at construction time
      throw new RuntimeException(e);
    }
  }

  @Override
  protected AlgorithmParameterSpec getAlgorithmParameters(final long nonce) {
    return new IvParameterSpec(ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
        .putLong(4, nonce)
        .array());
  }

  @Override
  public String getName() {
    return "ChaChaPoly";
  }

  @Override
  public Key buildKey(final byte[] keyBytes) {
    return new SecretKeySpec(keyBytes, "RAW");
  }
}
