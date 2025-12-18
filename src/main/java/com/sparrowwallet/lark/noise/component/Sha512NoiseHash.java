package com.sparrowwallet.lark.noise.component;

import javax.crypto.Mac;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class Sha512NoiseHash implements NoiseHash {

  private static final String MESSAGE_DIGEST_ALGORITHM = "SHA-512";
  private static final String HMAC_ALGORITHM = "HmacSHA512";

  public Sha512NoiseHash() throws NoSuchAlgorithmException {
    // Fail fast: check once if SHA-512 is supported so we don't have to worry about exceptions later
    MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM);
    Mac.getInstance(HMAC_ALGORITHM);
  }

  @Override
  public String getName() {
    return "SHA512";
  }

  @Override
  public MessageDigest getMessageDigest() {
    try {
      return MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM);
    } catch (final NoSuchAlgorithmException e) {
      throw new AssertionError("Previously-available message digest algorithm must remain available", e);
    }
  }

  @Override
  public Mac getHmac() {
    try {
      return Mac.getInstance(HMAC_ALGORITHM);
    } catch (final NoSuchAlgorithmException e) {
      throw new AssertionError("Previously-available HMAC algorithm must remain available", e);
    }
  }

  @Override
  public int getHashLength() {
    return 64;
  }
}
