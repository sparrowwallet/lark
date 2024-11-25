package com.sparrowwallet.lark.bitbox02.noise.crypto;

import javax.crypto.Mac;

public class HmacBlake2s256Mac extends Mac {

  public HmacBlake2s256Mac() {
    super(new HmacBlake2s256Spi(), null, "HmacBLAKE2s256");
  }
}
