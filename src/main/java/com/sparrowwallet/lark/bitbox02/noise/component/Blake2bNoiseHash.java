package com.sparrowwallet.lark.bitbox02.noise.component;

import com.sparrowwallet.lark.bitbox02.noise.crypto.Blake2b512MessageDigest;
import com.sparrowwallet.lark.bitbox02.noise.crypto.HmacBlake2b512Mac;

import javax.crypto.Mac;
import java.security.MessageDigest;

class Blake2bNoiseHash implements NoiseHash {

  private final Blake2b512MessageDigest messageDigest;
  private final HmacBlake2b512Mac hmac;

  public Blake2bNoiseHash() {
    this.messageDigest = new Blake2b512MessageDigest();
    this.hmac = new HmacBlake2b512Mac();
  }

  @Override
  public String getName() {
    return "BLAKE2b";
  }

  @Override
  public MessageDigest getMessageDigest() {
    return messageDigest;
  }

  @Override
  public Mac getHmac() {
    return hmac;
  }

  @Override
  public int getHashLength() {
    return 64;
  }
}
