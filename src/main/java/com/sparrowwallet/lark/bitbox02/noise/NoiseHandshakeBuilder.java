package com.sparrowwallet.lark.bitbox02.noise;

import com.sparrowwallet.lark.bitbox02.noise.component.*;

import javax.annotation.Nullable;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.List;
import java.util.Objects;

/**
 * <p>A Noise handshake builder constructs {@link NoiseHandshake} instances with known handshake patterns and roles.
 * In contrast to {@link NamedProtocolHandshakeBuilder}, this builder provides compile-time checks that all required
 * keys are provided, but places the burden of selecting protocol components (key agreement algorithms, ciphers, and
 * hash algorithms) on the caller.</p>
 *
 * <p>Callers may specify the cryptographic components of a Noise protocol by providing a full Noise protocol name…</p>
 *
 * {@snippet file="NoiseHandshakeBuilderExample.java" region="ik-handshake-protocol-name"}
 *
 * <p>…or by specifying the name of each component individually:</p>
 *
 * {@snippet file="NoiseHandshakeBuilderExample.java" region="ik-handshake-component-names"}
 *
 * @see NamedProtocolHandshakeBuilder
 */
@SuppressWarnings("unused")
public class NoiseHandshakeBuilder {

  private final NoiseHandshake.Role role;
  private final HandshakePattern handshakePattern;

  @Nullable private final KeyPair localStaticKeyPair;
  @Nullable private final PublicKey remoteStaticPublicKey;
  @Nullable private final byte[] preSharedKey;

  @Nullable private byte[] prologue;

  @Nullable private NoiseCipher cipher;
  @Nullable private NoiseHash hash;
  @Nullable private NoiseKeyAgreement keyAgreement;

  private NoiseHandshakeBuilder(final NoiseHandshake.Role role,
                                final HandshakePattern handshakePattern,
                                @Nullable final KeyPair localStaticKeyPair,
                                @Nullable final PublicKey remoteStaticPublicKey,
                                @Nullable final byte[] preSharedKey) {

    this.role = role;
    this.handshakePattern = handshakePattern;
    this.localStaticKeyPair = localStaticKeyPair;
    this.remoteStaticPublicKey = remoteStaticPublicKey;

    if (preSharedKey != null && preSharedKey.length != 32) {
      throw new IllegalArgumentException("Pre-shared keys must be exactly 32 bytes");
    }

    this.preSharedKey = preSharedKey;
  }

  /**
   * Sets the prologue for this handshake.
   *
   * @param prologue the prologue for this handshake; may be {@code null}
   *
   * @return a reference to this handshake builder
   */
  public NoiseHandshakeBuilder setPrologue(@Nullable final byte[] prologue) {
    this.prologue = prologue;
    return this;
  }

  /**
   * Sets the cryptographic components (key agreement, cipher, and hash algorithms) for this handshake from a full Noise
   * protocol name.
   *
   * @param protocolName the Noise protocol name from which to choose cryptographic components for this handshake
   *
   * @return a reference to this handshake builder
   *
   * @throws NoSuchAlgorithmException if one or more of the components in the given protocol name is not supported by
   * the current JVM
   * @throws IllegalArgumentException if the given protocol name is not a valid Noise protocol name or if its handshake
   * pattern does not match the handshake pattern selected for this handshake
   *
   * @see NoiseKeyAgreement#getInstance(String)
   * @see NoiseCipher#getInstance(String)
   * @see NoiseHash#getInstance(String)
   */
  public NoiseHandshakeBuilder setComponentsFromProtocolName(final String protocolName) throws NoSuchAlgorithmException {
    final String expectedPrefix = "Noise_" + handshakePattern.getName() + "_";

    if (!protocolName.startsWith(expectedPrefix)) {
      throw new IllegalArgumentException("Protocol name must be a Noise protocol name beginning with \"" + expectedPrefix + "\"");
    }

    final String[] componentNames = protocolName.substring(expectedPrefix.length()).split("_");

    if (componentNames.length != 3) {
      throw new IllegalArgumentException("Protocol name must be a valid Noise protocol name");
    }

    return setKeyAgreement(componentNames[0])
        .setCipher(componentNames[1])
        .setHash(componentNames[2]);
  }

  /**
   * Sets the cipher to be used by this handshake.
   *
   * @param cipherName the name of the Noise cipher to be used by this handshake
   *
   * @return a reference to this handshake builder
   *
   * @throws NoSuchAlgorithmException if the named algorithm is not supported by the current JVM
   * @throws IllegalArgumentException if the given name is not recognized as a Noise cipher name
   *
   * @see NoiseCipher#getInstance(String)
   */
  public NoiseHandshakeBuilder setCipher(final String cipherName) throws NoSuchAlgorithmException {
    this.cipher = NoiseCipher.getInstance(Objects.requireNonNull(cipherName, "Cipher must not be null"));
    return this;
  }

  /**
   * Sets the hash algorithm to be used by this handshake.
   *
   * @param hashName the name of the Noise hash to be used by this handshake
   *
   * @return a reference to this handshake builder
   *
   * @throws NoSuchAlgorithmException if the named algorithm is not supported by the current JVM
   * @throws IllegalArgumentException if the given name is not recognized as a Noise hash name
   *
   * @see NoiseCipher#getInstance(String)
   */
  public NoiseHandshakeBuilder setHash(final String hashName) throws NoSuchAlgorithmException {
    this.hash = NoiseHash.getInstance(Objects.requireNonNull(hashName, "Hash must not be null"));
    return this;
  }

  /**
   * Sets the key agreement algorithm to be used by this handshake.
   *
   * @param keyAgreementName the name of the Noise key agreement to be used by this handshake
   *
   * @return a reference to this handshake builder
   *
   * @throws NoSuchAlgorithmException if the named algorithm is not supported by the current JVM
   * @throws IllegalArgumentException if the given name is not recognized as a Noise key agreement algorithm name
   *
   * @see NoiseCipher#getInstance(String)
   */
  public NoiseHandshakeBuilder setKeyAgreement(final String keyAgreementName) throws NoSuchAlgorithmException {
    this.keyAgreement = NoiseKeyAgreement.getInstance(Objects.requireNonNull(keyAgreementName, "Key agreement algorithm must not be null"));
    return this;
  }

  /**
   * Constructs a Noise handshake with the previously-specified handshake pattern, role key material and cryptographic
   * components.
   *
   * @return a Noise handshake instance with the previously-specified handshake pattern, role key material and
   * cryptographic components
   *
   * @throws IllegalStateException if one or more cryptographic components has not been specified
   *
   * @see #setKeyAgreement(String)
   * @see #setCipher(String)
   * @see #setHash(String)
   */
  public NoiseHandshake build() {
    if (cipher == null) {
      throw new IllegalStateException("Must set a cipher before building a Noise handshake");
    }

    if (hash == null) {
      throw new IllegalArgumentException("Must set a hashing algorithm before building a Noise handshake");
    }

    if (keyAgreement == null) {
      throw new IllegalArgumentException("Must set a key agreement algorithm before building a Noise handshake");
    }

    return new NoiseHandshake(role,
        handshakePattern,
        keyAgreement,
        cipher,
        hash,
        prologue,
        localStaticKeyPair,
        null,
        remoteStaticPublicKey,
        null,
        preSharedKey != null ? List.of(preSharedKey) : null);
  }

  // The following initializer methods are auto-generated by GenerateHandshakeBuilderApp

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * N handshake.
   *
   *
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forNInitiator(final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("N"),
          null,
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * N handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forNResponder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("N"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * K handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forKInitiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("K"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * K handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forKResponder(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("K"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * X handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forXInitiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("X"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * X handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forXResponder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("X"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * NN handshake.
   *
   *
   *
   *
   *
   * @return a new Noise handshake builder
   *
   *
   */
  public static NoiseHandshakeBuilder forNNInitiator() {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("NN"),
          null,
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * NN handshake.
   *
   *
   *
   *
   *
   * @return a new Noise handshake builder
   *
   *
   */
  public static NoiseHandshakeBuilder forNNResponder() {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("NN"),
          null,
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * KN handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forKNInitiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("KN"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * KN handshake.
   *
   *
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forKNResponder(final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("KN"),
          null,
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * NK handshake.
   *
   *
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forNKInitiator(final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("NK"),
          null,
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * NK handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forNKResponder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("NK"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * KK handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forKKInitiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("KK"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * KK handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forKKResponder(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("KK"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * NX handshake.
   *
   *
   *
   *
   *
   * @return a new Noise handshake builder
   *
   *
   */
  public static NoiseHandshakeBuilder forNXInitiator() {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("NX"),
          null,
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * NX handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forNXResponder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("NX"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * KX handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forKXInitiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("KX"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * KX handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forKXResponder(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("KX"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * XN handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forXNInitiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("XN"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * XN handshake.
   *
   *
   *
   *
   *
   * @return a new Noise handshake builder
   *
   *
   */
  public static NoiseHandshakeBuilder forXNResponder() {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("XN"),
          null,
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * IN handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forINInitiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("IN"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * IN handshake.
   *
   *
   *
   *
   *
   * @return a new Noise handshake builder
   *
   *
   */
  public static NoiseHandshakeBuilder forINResponder() {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("IN"),
          null,
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * XK handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forXKInitiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("XK"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * XK handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forXKResponder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("XK"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * IK handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forIKInitiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("IK"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * IK handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forIKResponder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("IK"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * XX handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forXXInitiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("XX"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * XX handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forXXResponder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("XX"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * IX handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forIXInitiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("IX"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * IX handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forIXResponder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("IX"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * NK1 handshake.
   *
   *
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forNK1Initiator(final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("NK1"),
          null,
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * NK1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forNK1Responder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("NK1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * NX1 handshake.
   *
   *
   *
   *
   *
   * @return a new Noise handshake builder
   *
   *
   */
  public static NoiseHandshakeBuilder forNX1Initiator() {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("NX1"),
          null,
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * NX1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forNX1Responder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("NX1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * X1N handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forX1NInitiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("X1N"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * X1N handshake.
   *
   *
   *
   *
   *
   * @return a new Noise handshake builder
   *
   *
   */
  public static NoiseHandshakeBuilder forX1NResponder() {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("X1N"),
          null,
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * X1K handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forX1KInitiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("X1K"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * X1K handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forX1KResponder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("X1K"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * XK1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forXK1Initiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("XK1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * XK1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forXK1Responder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("XK1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * X1K1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forX1K1Initiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("X1K1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * X1K1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forX1K1Responder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("X1K1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * X1X handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forX1XInitiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("X1X"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * X1X handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forX1XResponder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("X1X"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * XX1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forXX1Initiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("XX1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * XX1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forXX1Responder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("XX1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * X1X1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forX1X1Initiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("X1X1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * X1X1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forX1X1Responder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("X1X1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * K1N handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forK1NInitiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("K1N"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * K1N handshake.
   *
   *
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forK1NResponder(final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("K1N"),
          null,
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * K1K handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forK1KInitiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("K1K"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * K1K handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forK1KResponder(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("K1K"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * KK1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forKK1Initiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("KK1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * KK1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forKK1Responder(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("KK1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * K1K1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forK1K1Initiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("K1K1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * K1K1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forK1K1Responder(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("K1K1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * K1X handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forK1XInitiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("K1X"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * K1X handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forK1XResponder(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("K1X"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * KX1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forKX1Initiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("KX1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * KX1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forKX1Responder(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("KX1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * K1X1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forK1X1Initiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("K1X1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * K1X1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forK1X1Responder(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("K1X1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * I1N handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forI1NInitiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("I1N"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * I1N handshake.
   *
   *
   *
   *
   *
   * @return a new Noise handshake builder
   *
   *
   */
  public static NoiseHandshakeBuilder forI1NResponder() {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("I1N"),
          null,
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * I1K handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forI1KInitiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("I1K"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * I1K handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forI1KResponder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("I1K"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * IK1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forIK1Initiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("IK1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * IK1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forIK1Responder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("IK1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * I1K1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forI1K1Initiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("I1K1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * I1K1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forI1K1Responder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("I1K1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * I1X handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forI1XInitiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("I1X"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * I1X handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forI1XResponder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("I1X"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * IX1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forIX1Initiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("IX1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * IX1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forIX1Responder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("IX1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * I1X1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forI1X1Initiator(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("I1X1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * I1X1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   *
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   */
  public static NoiseHandshakeBuilder forI1X1Responder(final KeyPair localStaticKeyPair) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("I1X1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          null);
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * Npsk0 handshake.
   *
   *
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forNPsk0Initiator(final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("Npsk0"),
          null,
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * Npsk0 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forNPsk0Responder(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("Npsk0"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * Kpsk0 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forKPsk0Initiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("Kpsk0"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * Kpsk0 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forKPsk0Responder(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("Kpsk0"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * Xpsk1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forXPsk1Initiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("Xpsk1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * Xpsk1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forXPsk1Responder(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("Xpsk1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * NNpsk0 handshake.
   *
   *
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forNNPsk0Initiator(final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("NNpsk0"),
          null,
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * NNpsk0 handshake.
   *
   *
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forNNPsk0Responder(final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("NNpsk0"),
          null,
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * NNpsk2 handshake.
   *
   *
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forNNPsk2Initiator(final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("NNpsk2"),
          null,
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * NNpsk2 handshake.
   *
   *
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forNNPsk2Responder(final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("NNpsk2"),
          null,
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * NKpsk0 handshake.
   *
   *
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forNKPsk0Initiator(final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("NKpsk0"),
          null,
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * NKpsk0 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forNKPsk0Responder(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("NKpsk0"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * NKpsk2 handshake.
   *
   *
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forNKPsk2Initiator(final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("NKpsk2"),
          null,
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * NKpsk2 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forNKPsk2Responder(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("NKpsk2"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * NXpsk2 handshake.
   *
   *
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forNXPsk2Initiator(final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("NXpsk2"),
          null,
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * NXpsk2 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forNXPsk2Responder(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("NXpsk2"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * XNpsk3 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forXNPsk3Initiator(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("XNpsk3"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * XNpsk3 handshake.
   *
   *
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forXNPsk3Responder(final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("XNpsk3"),
          null,
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * XKpsk3 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forXKPsk3Initiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("XKpsk3"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * XKpsk3 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forXKPsk3Responder(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("XKpsk3"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * XXpsk3 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forXXPsk3Initiator(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("XXpsk3"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * XXpsk3 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forXXPsk3Responder(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("XXpsk3"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * KNpsk0 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forKNPsk0Initiator(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("KNpsk0"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * KNpsk0 handshake.
   *
   *
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forKNPsk0Responder(final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("KNpsk0"),
          null,
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * KNpsk2 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forKNPsk2Initiator(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("KNpsk2"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * KNpsk2 handshake.
   *
   *
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forKNPsk2Responder(final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("KNpsk2"),
          null,
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * KKpsk0 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forKKPsk0Initiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("KKpsk0"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * KKpsk0 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forKKPsk0Responder(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("KKpsk0"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * KKpsk2 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forKKPsk2Initiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("KKpsk2"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * KKpsk2 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forKKPsk2Responder(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("KKpsk2"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in a
   * KXpsk2 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forKXPsk2Initiator(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("KXpsk2"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in a
   * KXpsk2 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forKXPsk2Responder(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("KXpsk2"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * INpsk1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forINPsk1Initiator(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("INpsk1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * INpsk1 handshake.
   *
   *
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forINPsk1Responder(final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("INpsk1"),
          null,
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * INpsk2 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forINPsk2Initiator(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("INpsk2"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * INpsk2 handshake.
   *
   *
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forINPsk2Responder(final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("INpsk2"),
          null,
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * IKpsk1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forIKPsk1Initiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("IKpsk1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * IKpsk1 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forIKPsk1Responder(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("IKpsk1"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * IKpsk2 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forIKPsk2Initiator(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("IKpsk2"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          Objects.requireNonNull(remoteStaticPublicKey, "Remote static public key must not be null"),
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * IKpsk2 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forIKPsk2Responder(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("IKpsk2"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the initiator in an
   * IXpsk2 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forIXPsk2Initiator(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.INITIATOR,
          HandshakePattern.getInstance("IXpsk2"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }

  /**
   * Constructs a new Noise handshake builder for the responder in an
   * IXpsk2 handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   *
   * @param preSharedKey the pre-shared key for this handshake; must not be {@code null}
   *
   * @return a new Noise handshake builder
   *
   * @throws NullPointerException if any required key {@code null}
   * @throws IllegalArgumentException if the given pre-shared key is not exactly 32 bytes long
   */
  public static NoiseHandshakeBuilder forIXPsk2Responder(final KeyPair localStaticKeyPair, final byte[] preSharedKey) {
    try {
      return new NoiseHandshakeBuilder(NoiseHandshake.Role.RESPONDER,
          HandshakePattern.getInstance("IXpsk2"),
          Objects.requireNonNull(localStaticKeyPair, "Local static key pair must not be null"),
          null,
          Objects.requireNonNull(preSharedKey, "Pre-shared key must not be null"));
    } catch (final NoSuchPatternException e) {
      throw new AssertionError("Statically-generated handshake pattern not found", e);
    }
  }
}
