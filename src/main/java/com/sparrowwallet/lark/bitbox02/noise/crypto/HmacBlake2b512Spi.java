package com.sparrowwallet.lark.bitbox02.noise.crypto;

class HmacBlake2b512Spi extends HmacSpi {

  protected HmacBlake2b512Spi() {
    super(new Blake2b512MessageDigest(), 128);
  }

  @Override
  protected int engineGetMacLength() {
    return 64;
  }
}
