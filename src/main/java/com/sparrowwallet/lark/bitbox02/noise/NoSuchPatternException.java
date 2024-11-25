package com.sparrowwallet.lark.bitbox02.noise;

/**
 * Indicates that a named pattern is not a recognized fundamental or deferred Noise handshake pattern and cannot be
 * derived by modifying a recognized fundamental or deferred Noise handshake pattern.
 */
public class NoSuchPatternException extends Exception {

  /**
   * Constructs a new "no such pattern" exception.
   *
   * @param patternName the name of the requested handshake pattern
   */
  public NoSuchPatternException(final String patternName) {
    super("No such handshake pattern: " + patternName);
  }
}
