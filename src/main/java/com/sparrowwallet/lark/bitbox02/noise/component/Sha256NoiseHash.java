package com.sparrowwallet.lark.bitbox02.noise.component;

import javax.crypto.Mac;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class Sha256NoiseHash implements NoiseHash {

  @Override
  public String getName() {
    return "SHA256";
  }

  @Override
  public MessageDigest getMessageDigest() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (final NoSuchAlgorithmException e) {
      throw new AssertionError("Every implementation of the Java platform is required to support SHA-256", e);
    }
  }

  @Override
  public Mac getHmac() {
    try {
      return Mac.getInstance("HmacSHA256");
    } catch (final NoSuchAlgorithmException e) {
      throw new AssertionError("Every implementation of the Java platform is required to support HmacSHA256", e);
    }
  }

  @Override
  public int getHashLength() {
    return 32;
  }
}
