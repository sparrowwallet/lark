package com.sparrowwallet.lark.bitbox02.noise.component;

import javax.crypto.KeyAgreement;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

class X25519KeyAgreement extends AbstractXECKeyAgreement {

  private static final String ALGORITHM = "X25519";
  private static final byte[] X509_PREFIX = HexFormat.of().parseHex("302a300506032b656e032100");

  public X25519KeyAgreement() throws NoSuchAlgorithmException {
    super(KeyAgreement.getInstance(ALGORITHM), KeyPairGenerator.getInstance(ALGORITHM), KeyFactory.getInstance(ALGORITHM));
  }

  @Override
  public String getName() {
    return "25519";
  }

  @Override
  public int getPublicKeyLength() {
    return 32;
  }

  @Override
  protected byte[] getX509Prefix() {
    return X509_PREFIX;
  }
}
