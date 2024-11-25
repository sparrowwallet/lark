package com.sparrowwallet.lark.bitbox02.noise;

import com.sparrowwallet.lark.bitbox02.noise.component.*;

import javax.annotation.Nullable;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.List;
import java.util.Objects;

/**
 * <p>A {@code NamedProtocolHandshakeBuilder} constructs {@link NoiseHandshake} instances given a full Noise protocol
 * name and a role (initiator or responder). In contrast to {@link NoiseHandshakeBuilder}, callers are responsible for
 * identifying and providing all required key material, which may vary with handshake pattern and role. For example, the
 * NN handshake pattern is defined as:</p>
 *
 * <pre>NN:
 *   -&gt; e
 *   &lt;- e, ee</pre>
 *
 * <p>…and so neither the initiator nor the responder requires any static or pre-shared keys:</p>
 *
 * {@snippet file="NamedProtocolHandshakeBuilderExample.java" region="nn-handshake"}
 *
 * <p>By contrast, the IK handshake pattern is defined as:</p>
 *
 * <pre>IK:
 *   &lt;- s
 *   ...
 *   -&gt; e, es, s, ss
 *   &lt;- e, ee, se</pre>
 *
 * <p>…and so the initiator needs a local static key pair and a remote static public key, while the responder needs only
 * a local static key pair:</p>
 *
 * {@snippet file="NamedProtocolHandshakeBuilderExample.java" region="ik-handshake"}
 *
 * @see NoiseHandshakeBuilder
 */
public class NamedProtocolHandshakeBuilder {

  private final HandshakePattern handshakePattern;
  private final NoiseKeyAgreement keyAgreement;
  private final NoiseCipher cipher;
  private final NoiseHash hash;

  private final NoiseHandshake.Role role;

  @Nullable private KeyPair localEphemeralKeyPair;
  @Nullable private KeyPair localStaticKeyPair;
  @Nullable private PublicKey remoteStaticPublicKey;
  @Nullable private List<byte[]> preSharedKeys;

  @Nullable private byte[] prologue;

  /**
   * Constructs a new Noise handshake for the given Noise protocol name and role.
   *
   * @param noiseProtocolName the full Noise protocol name for which to construct a handshake object
   * @param role the role for the handshake object
   *
   * @throws NoSuchAlgorithmException if one or more components of the Noise protocol was not recognized or is not
   * supported in the current JVM
   * @throws NoSuchPatternException if the handshake pattern in the Noise protocol name was not recognized or is invalid
   */
  public NamedProtocolHandshakeBuilder(final String noiseProtocolName, final NoiseHandshake.Role role)
      throws NoSuchAlgorithmException, NoSuchPatternException {

    final String[] components = noiseProtocolName.split("_");

    if (components.length != 5) {
      throw new IllegalArgumentException("Invalid Noise protocol name; did not contain five sections");
    }

    if (!"Noise".equals(components[0])) {
      throw new IllegalArgumentException("Noise protocol names must begin with \"Noise_\"");
    }

    this.handshakePattern = HandshakePattern.getInstance(components[1]);
    this.keyAgreement = NoiseKeyAgreement.getInstance(components[2]);
    this.cipher = NoiseCipher.getInstance(components[3]);
    this.hash = NoiseHash.getInstance(components[4]);

    this.role = role;
  }

  /**
   * Sets the prologue for this handshake.
   *
   * @param prologue the prologue for this handshake; may be {@code null}
   *
   * @return a reference to this handshake builder
   */
  public NamedProtocolHandshakeBuilder setPrologue(@Nullable final byte[] prologue) {
    this.prologue = prologue;
    return this;
  }

  NamedProtocolHandshakeBuilder setLocalEphemeralKeyPair(@Nullable final KeyPair localEphemeralKeyPair) {
    this.localEphemeralKeyPair = localEphemeralKeyPair;
    return this;
  }

  /**
   * Sets the local static key pair for this handshake.
   *
   * @param localStaticKeyPair the local static key pair for this handshake; must not be {@code null}
   * 
   * @return a reference to this handshake builder
   * 
   * @throws IllegalStateException if the chosen handshake pattern does not allow for local static keys
   *
   * @see HandshakePattern#requiresLocalStaticKeyPair(NoiseHandshake.Role) 
   */
  public NamedProtocolHandshakeBuilder setLocalStaticKeyPair(final KeyPair localStaticKeyPair) {
    if (!handshakePattern.requiresLocalStaticKeyPair(role)) {
      throw new IllegalStateException(handshakePattern.getName() + " handshake pattern does not allow local static keys for " + role + " role");
    }

    this.localStaticKeyPair = Objects.requireNonNull(localStaticKeyPair, "If set, local static key pair may not be null");
    return this;
  }

  /**
   * Sets the remote static public key for this handshake.
   *
   * @param remoteStaticPublicKey the remote static public key for this handshake; must not be {@code null}
   *
   * @return a reference to this builder
   *
   * @throws IllegalStateException if the chosen handshake pattern does not allow for remote static keys
   * 
   * @see HandshakePattern#requiresRemoteStaticPublicKey(NoiseHandshake.Role) 
   */
  public NamedProtocolHandshakeBuilder setRemoteStaticPublicKey(final PublicKey remoteStaticPublicKey) {
    if (!handshakePattern.requiresRemoteStaticPublicKey(role)) {
      throw new IllegalStateException(handshakePattern.getName() + " handshake pattern does not allow remote static key for " + role + " role");
    }

    this.remoteStaticPublicKey = Objects.requireNonNull(remoteStaticPublicKey, "If set, remote static public key may not be null");
    return this;
  }

  /**
   * Sets the pre-shared keys for this handshake.
   *
   * @param preSharedKeys the pre-shared keys for this handshake; must not be {@code null}
   *
   * @return a reference to this builder
   *
   * @throws IllegalStateException if the chosen handshake pattern does not allow for pre-shared keys
   * @throws IllegalArgumentException if the given list of pre-shared keys has a length that does not match the number
   * of pre-shared keys required by the chosen handshake pattern or if any key is not exactly 32 bytes in length
   *
   * @see HandshakePattern#getRequiredPreSharedKeyCount()
   */
  public NamedProtocolHandshakeBuilder setPreSharedKeys(final List<byte[]> preSharedKeys) {
    final int requiredPreSharedKeys = handshakePattern.getRequiredPreSharedKeyCount();

    if (requiredPreSharedKeys == 0) {
      throw new IllegalStateException(handshakePattern.getName() + " handshake pattern does not allow pre-shared keys");
    }

    if (preSharedKeys.size() != requiredPreSharedKeys) {
      throw new IllegalArgumentException(handshakePattern.getName() + " requires exactly " + requiredPreSharedKeys + " pre-shared keys");
    }

    if (preSharedKeys.stream().anyMatch(preSharedKey -> preSharedKey.length != 32)) {
      throw new IllegalArgumentException("Pre-shared keys must be exactly 32 bytes");
    }

    this.preSharedKeys = preSharedKeys;
    return this;
  }

  /**
   * Constructs a Noise handshake with the previously-configured protocol and keys.
   *
   * @return a Noise handshake with the previously-configured protocol and keys
   *
   * @throws IllegalStateException if any keys required by the chosen handshake pattern have not been set
   *
   * @see HandshakePattern#requiresLocalStaticKeyPair(NoiseHandshake.Role)
   * @see HandshakePattern#requiresRemoteStaticPublicKey(NoiseHandshake.Role)
   * @see HandshakePattern#getRequiredPreSharedKeyCount()
   */
  public NoiseHandshake build() {
    if (handshakePattern.requiresRemoteStaticPublicKey(role) && remoteStaticPublicKey == null) {
      throw new IllegalStateException(handshakePattern.getName() + " handshake pattern requires a remote static public key for the " + role + " role");
    }

    if (handshakePattern.requiresLocalStaticKeyPair(role) && localStaticKeyPair == null) {
      throw new IllegalStateException(handshakePattern.getName() + " handshake pattern requires a local static key pair for the " + role + " role");
    }

    final int requiredPreSharedKeyCount = handshakePattern.getRequiredPreSharedKeyCount();

    if (requiredPreSharedKeyCount > 0 && (preSharedKeys == null || preSharedKeys.size() != requiredPreSharedKeyCount)) {
      throw new IllegalStateException(handshakePattern.getName() + " handshake pattern requires " + requiredPreSharedKeyCount + " pre-shared keys");
    }

    return new NoiseHandshake(role,
        handshakePattern,
        keyAgreement,
        cipher,
        hash,
        prologue,
        localStaticKeyPair,
        localEphemeralKeyPair,
        remoteStaticPublicKey,
        null,
        preSharedKeys);
  }
}
