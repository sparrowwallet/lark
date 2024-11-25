package com.sparrowwallet.lark.bitbox02.noise.crypto;

import javax.crypto.Mac;

public class HmacBlake2b512Mac extends Mac {

  public HmacBlake2b512Mac() {
    super(new HmacBlake2b512Spi(), null, "HmacBLAKE2b512");
  }
}
