package com.sparrowwallet.lark.bitbox02.noise.crypto;

import java.security.MessageDigest;

public class Blake2b512MessageDigest extends MessageDigest {

  private final Blake2bMessageDigestSpi messageDigestSpi;

  public Blake2b512MessageDigest() {
    super("BLAKE2b-512");

    messageDigestSpi = new Blake2bMessageDigestSpi(64);
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
