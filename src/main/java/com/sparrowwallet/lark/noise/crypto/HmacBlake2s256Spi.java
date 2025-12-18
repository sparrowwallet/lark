package com.sparrowwallet.lark.noise.crypto;

class HmacBlake2s256Spi extends HmacSpi {

  HmacBlake2s256Spi() {
    super(new Blake2s256MessageDigest(), 64);
  }

  @Override
  protected int engineGetMacLength() {
    return 32;
  }
}
