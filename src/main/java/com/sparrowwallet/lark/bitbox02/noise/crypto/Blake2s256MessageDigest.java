package com.sparrowwallet.lark.bitbox02.noise.crypto;

import java.security.MessageDigest;

public class Blake2s256MessageDigest extends MessageDigest {

  private final Blake2sMessageDigestSpi messageDigestSpi;

  public Blake2s256MessageDigest() {
    super("BLAKE2s-256");

    messageDigestSpi = new Blake2sMessageDigestSpi(32);
  }

  @Override
  protected int engineGetDigestLength() {
    return messageDigestSpi.engineGetDigestLength();
  }

  @Override
  protected void engineUpdate(final byte input) {
    messageDigestSpi.engineUpdate(input);
  }

  @Override
  protected void engineUpdate(final byte[] input, final int offset, final int len) {
    messageDigestSpi.engineUpdate(input, offset, len);
  }

  @Override
  protected byte[] engineDigest() {
    return messageDigestSpi.engineDigest();
  }

  @Override
  protected void engineReset() {
    messageDigestSpi.engineReset();
  }
}
