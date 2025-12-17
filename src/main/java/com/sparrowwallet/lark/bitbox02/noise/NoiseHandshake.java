package com.sparrowwallet.lark.bitbox02.noise;

import com.sparrowwallet.lark.bitbox02.noise.component.NoiseCipher;
import com.sparrowwallet.lark.bitbox02.noise.component.NoiseHash;
import com.sparrowwallet.lark.bitbox02.noise.component.NoiseKeyAgreement;

import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * <p>A {@code NoiseHandshake} instance is responsible for encrypting and decrypting the messages that comprise a Noise
 * handshake. Once a Noise handshake instance has finished exchanging handshake messages, it can produce a Noise
 * transport object for steady-state encryption and decryption of Noise transport messages.</p>
 *
 * <p>Noise handshake messages contain key material and an optional payload. The security properties for the optional
 * payload vary by handshake pattern, message, and sender role. Callers are responsible for verifying that the security
 * properties associated with ny handshake message are suitable for their use case. Please see
 * <a href="https://noiseprotocol.org/noise.html#payload-security-properties">The Noise Protocol Framework - Payload
 * security properties</a> for a complete explanation.</p>
 *
 * <p>Generally speaking, the initiator and responder alternate sending and receiving messages until all messages in the
 * handshake pattern have been exchanged. At that point, callers transform (or "split" in the terminology of the Noise
 * Protocol Framework specification) the Noise handshake into a Noise transport instance appropriate for the handshake
 * type (i.e. one-way or interactive) and pass Noise transport messages between the initiator and responder as
 * needed.</p>
 *
 * <p>Noise handshake instances are stateful and are <em>not</em> thread-safe.</p>
 *
 * <h2>Interactive patterns</h2>
 *
 * <p>In the most common case, Noise handshakes implement an interactive pattern in which both parties will send and
 * receive messages to one another once the handshake is complete. As an example, the NN interactive handshake pattern
 * is defined as:</p>
 *
 * <pre>NN:
 *   -&gt; e
 *   &lt;- e, ee</pre>
 *
 * <p>The parties in an NN handshake exchange messages until all required messages have been exchanged, then the
 * handshake instances yield interactive transport instances:</p>
 *
 * {@snippet file="NoiseHandshakeExample.java" region="interactive-handshake"}
 *
 * <h2>One-way patterns</h2>
 *
 * <p>Noise handshakes may also use one-way patterns. As the Noise Protocol Framework specification notes:</p>
 *
 * <blockquote>These patterns could be used to encrypt files, database records, or other non-interactive data
 * streams.</blockquote>
 *
 * <p>One-way handshakes exchange handshake messages in the same way as interactive handshakes, but instead of
 * producing interactive {@link NoiseTransport} instances, one-way handshakes produce a one-way
 * {@link NoiseTransportWriter} for initiators or {@link NoiseTransportReader} for responders. As an example, the N
 * handshake pattern is defined as:</p>
 *
 * <pre>N:
 *   &lt;- s
 *   ...
 *   -&gt; e, es</pre>
 *
 * <p>The parties in an N handshake exchange messages as usual, then the handshake instances yield one-way transport
 * instances:</p>
 *
 * {@snippet file="NoiseHandshakeExample.java" region="one-way-handshake"}
 *
 * <h2>Fallback patterns</h2>
 *
 * <p>Noise handshakes can "fall back" to another pattern to handle certain kinds of errors. As an example, the
 * <a href="https://noiseprotocol.org/noise.html#noise-pipes">Noise Pipes</a> compound protocol expects that initiators
 * will usually have the responder's static public key available from a previous "full" (XX) handshake, and can use an
 * abbreviated (IK) handshake pattern with that static key set via a pre-handshake message. If the responder can't
 * decrypt a message from the initiator, though, it might conclude that the initiator has a stale copy of its public key
 * and can fall back to a "full" (XXfallback) handshake.</p>
 *
 * <p>The IK handshake pattern is defined as:</p>
 *
 * <pre>IK:
 *   &lt;- s
 *   ...
 *   -&gt; e, es, s, ss
 *   &lt;- e, ee, se</pre>
 *
 * <p>…and the XXfallback pattern is defined as:</p>
 *
 * <pre>XXfallback:
 *   -&gt; e
 *   ...
 *   &lt;- e, ee, s, es
 *   -&gt; s, se</pre>
 *
 * <p>As an example, consider a scenario where the initiator of an IK handshake has a "stale" static key for the
 * responder:</p>
 *
 * {@snippet file="NoiseHandshakeExample.java" region="build-ik-handshake"}
 *
 * <p>The initiator sends its first message to the responder, which won't be able to decrypt the message due to the
 * static key disagreement:</p>
 *
 * {@snippet file="NoiseHandshakeExample.java" region="send-initiator-static-key-message"}
 *
 * <p>Rather than simply failing the handshake (assuming both the initiator and responder are expecting that a fallback
 * may happen), the responder can fall back to the XXfallback pattern, reusing the ephemeral key it already received
 * from the initiator as a pre-handshake message, and write a message to continue the XXfallback pattern:</p>
 *
 * {@snippet file="NoiseHandshakeExample.java" region="responder-fallback"}
 *
 * <p>The initiator will fail to decrypt the message from the responder:</p>
 *
 * {@snippet file="NoiseHandshakeExample.java" region="initiator-read-fallback-message"}
 *
 * <p>Like the responder, the initiator can take the decryption failure as a cue to fall back to the XXfallback pattern,
 * then read the message and finish the handshake:</p>
 *
 * {@snippet file="NoiseHandshakeExample.java" region="initiator-fallback"}
 *
 * <p>Once the handshake is finished, the transition to the transport phase of the protocol continues as usual.</p>
 *
 * @see NamedProtocolHandshakeBuilder
 * @see NoiseHandshakeBuilder
 *
 * @see <a href="https://noiseprotocol.org/noise.html#payload-security-properties">The Noise Protocol Framework - Payload security proprties</a>
 */
public class NoiseHandshake {

  private final String noiseProtocolName;
  private final HandshakePattern handshakePattern;
  private final Role role;

  private int currentMessagePattern = 0;
  private boolean hasSplit = false;
  private boolean hasFallenBack = false;

  private final CipherState cipherState;
  private final NoiseHash noiseHash;
  private final NoiseKeyAgreement keyAgreement;

  private final byte[] chainingKey;
  private final byte[] hash;

  private final byte[] prologue;

  private KeyPair localEphemeralKeyPair;

  private PublicKey remoteEphemeralPublicKey;

  private KeyPair localStaticKeyPair;

  private PublicKey remoteStaticPublicKey;

  private final List<byte[]> preSharedKeys;

  private int currentPreSharedKey;

  static final int MAX_NOISE_MESSAGE_SIZE = 65_535;

  private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
  private static final ByteBuffer EMPTY_BYTE_BUFFER = ByteBuffer.wrap(EMPTY_BYTE_ARRAY);

  /**
   * An enumeration of roles within a Noise handshake.
   */
  public enum Role {
    /**
     * Indicates that a party is the initiator of a Noise handshake.
     */
    INITIATOR,

    /**
     * Indicates that a party is the responder in a Noise handshake.
     */
    RESPONDER
  }

  NoiseHandshake(final Role role,
                 final HandshakePattern handshakePattern,
                 final NoiseKeyAgreement keyAgreement,
                 final NoiseCipher noiseCipher,
                 final NoiseHash noiseHash,
                 final byte[] prologue,
                 final KeyPair localStaticKeyPair,
                 final KeyPair localEphemeralKeyPair,
                 final PublicKey remoteStaticPublicKey,
                 final PublicKey remoteEphemeralPublicKey,
                 final List<byte[]> preSharedKeys) {

    this.handshakePattern = handshakePattern;
    this.role = role;

    this.cipherState = new CipherState(noiseCipher);
    this.noiseHash = noiseHash;
    this.keyAgreement = keyAgreement;

    if (handshakePattern.requiresLocalStaticKeyPair(role)) {
      if (localStaticKeyPair == null) {
        throw new IllegalArgumentException(handshakePattern.getName() + " handshake pattern requires a local static key pair for " + role + " role");
      }

      try {
        keyAgreement.checkKeyPair(localStaticKeyPair);
      } catch (final InvalidKeyException e) {
        throw new IllegalArgumentException("Incompatible local static key pair", e);
      }
    } else {
      if (localStaticKeyPair != null) {
        throw new IllegalArgumentException(handshakePattern.getName() + " handshake pattern does not allow a local static key pair for " + role + " role");
      }
    }

    if (handshakePattern.requiresRemoteStaticPublicKey(role)) {
      if (remoteStaticPublicKey == null) {
        throw new IllegalArgumentException(handshakePattern.getName() + " handshake pattern requires a remote static public key for " + role + " role");
      }

      try {
        keyAgreement.checkPublicKey(remoteStaticPublicKey);
      } catch (final InvalidKeyException e) {
        throw new IllegalArgumentException("Incompatible remote static public key", e);
      }
    } else {
      if (remoteStaticPublicKey != null) {
        throw new IllegalArgumentException(handshakePattern.getName() + " handshake pattern does not allow a remote static public key for " + role + " role");
      }
    }

    if (handshakePattern.requiresRemoteEphemeralPublicKey(role)) {
      if (remoteEphemeralPublicKey == null) {
        throw new IllegalArgumentException(handshakePattern.getName() + " handshake pattern requires a remote ephemeral public key for " + role + " role");
      }

      try {
        keyAgreement.checkPublicKey(remoteEphemeralPublicKey);
      } catch (final InvalidKeyException e) {
        throw new IllegalArgumentException("Incompatible remote ephemeral public key", e);
      }
    } else {
      if (remoteEphemeralPublicKey != null) {
        throw new IllegalArgumentException(handshakePattern.getName() + " handshake pattern does not allow a remote ephemeral public key for " + role + " role");
      }
    }

    final int requiredPreSharedKeys = handshakePattern.getRequiredPreSharedKeyCount();

    if (requiredPreSharedKeys > 0) {
      if (preSharedKeys == null || preSharedKeys.size() != requiredPreSharedKeys) {
        throw new IllegalArgumentException(handshakePattern.getName() + " handshake pattern requires " + requiredPreSharedKeys + " pre-shared keys");
      }

      if (preSharedKeys.stream().anyMatch(preSharedKey -> preSharedKey.length != 32)) {
        throw new IllegalArgumentException("Pre-shared keys must be exactly 32 bytes");
      }
    } else {
      if (preSharedKeys != null && !preSharedKeys.isEmpty()) {
        throw new IllegalArgumentException(handshakePattern.getName() + " handshake pattern does not allow pre-shared keys");
      }
    }

    if (localEphemeralKeyPair != null) {
      try {
        keyAgreement.checkKeyPair(localEphemeralKeyPair);
      } catch (final InvalidKeyException e) {
        throw new IllegalArgumentException("Invalid local ephemeral key pair", e);
      }
    }

    this.prologue = prologue;

    this.localStaticKeyPair = localStaticKeyPair;
    this.localEphemeralKeyPair = localEphemeralKeyPair;
    this.remoteStaticPublicKey = remoteStaticPublicKey;
    this.remoteEphemeralPublicKey = remoteEphemeralPublicKey;
    this.preSharedKeys = preSharedKeys;

    this.noiseProtocolName = "Noise_" +
        handshakePattern.getName() + "_" +
        keyAgreement.getName() + "_" +
        noiseCipher.getName() + "_" +
        noiseHash.getName();

    hash = new byte[noiseHash.getHashLength()];

    final byte[] protocolNameBytes = noiseProtocolName.getBytes(StandardCharsets.UTF_8);

    final MessageDigest messageDigest = noiseHash.getMessageDigest();

    if (protocolNameBytes.length <= messageDigest.getDigestLength()) {
      System.arraycopy(protocolNameBytes, 0, hash, 0, protocolNameBytes.length);
    } else {
      try {
        messageDigest.reset();
        messageDigest.update(protocolNameBytes);
        messageDigest.digest(hash, 0, hash.length);
      } catch (final DigestException e) {
        // This should never happen
        throw new AssertionError(e);
      }
    }

    chainingKey = hash.clone();
    mixHash(prologue != null ? prologue : EMPTY_BYTE_ARRAY);

    Arrays.stream(handshakePattern.getPreMessagePatterns())
        // Process the initiator's keys first; "initiator" comes before "responder" in the `Role` enum, and so we don't
        // need a specialized comparator
        .sorted(Comparator.comparing(HandshakePattern.MessagePattern::sender))
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens())
            .map(token -> switch (token) {
              case E -> {
                final PublicKey ephemeralPublicKey;

                if (messagePattern.sender() == role) {
                  ephemeralPublicKey = localEphemeralKeyPair != null ? localEphemeralKeyPair.getPublic() : null;
                } else {
                  ephemeralPublicKey = remoteEphemeralPublicKey;
                }

                if (ephemeralPublicKey == null) {
                  throw new IllegalStateException("Ephemeral public key for " + messagePattern.sender() + " role must not be null");
                }

                yield ephemeralPublicKey;
              }
              case S -> {
                final PublicKey staticPublicKey;

                if (messagePattern.sender() == role) {
                  staticPublicKey = localStaticKeyPair != null ? localStaticKeyPair.getPublic() : null;
                } else {
                  staticPublicKey = remoteStaticPublicKey;
                }

                if (staticPublicKey == null) {
                  throw new IllegalStateException("Static public key for " + messagePattern.sender() + " role must not be null");
                }

                yield staticPublicKey;
              }
              case EE, ES, SE, SS, PSK ->
                  throw new IllegalArgumentException("Key-mixing tokens must not appear in pre-messages");
            }))
        .forEach(publicKey -> mixHash(keyAgreement.serializePublicKey(publicKey)));
  }

  /**
   * Returns the full name of the Noise protocol for this handshake.
   *
   * @return the full name of the Noise protocol for this handshake
   *
   * @see <a href="https://noiseprotocol.org/noise.html#protocol-names-and-modifiers">The Noise Protocol Framework - Protocol names and modifiers</a>
   */
  public String getNoiseProtocolName() {
    return noiseProtocolName;
  }

  private void mixKey(final byte[] inputKeyMaterial) {
    final byte[][] derivedKeys = noiseHash.deriveKeys(chainingKey, inputKeyMaterial, 2);

    System.arraycopy(derivedKeys[0], 0, chainingKey, 0, derivedKeys[0].length);
    cipherState.setKey(derivedKeys[1]);
  }

  private void mixHash(final byte[] bytes) {
    mixHash(bytes, 0, bytes.length);
  }

  private void mixHash(final byte[] bytes, final int offset, final int length) {
    final MessageDigest messageDigest = noiseHash.getMessageDigest();

    try {
      messageDigest.reset();
      messageDigest.update(hash);
      messageDigest.update(bytes, offset, length);
      messageDigest.digest(hash, 0, hash.length);
    } catch (final DigestException e) {
      // This should never happen
      throw new AssertionError(e);
    }
  }

  private void mixHash(final ByteBuffer byteBuffer) {
    final MessageDigest messageDigest = noiseHash.getMessageDigest();

    try {
      messageDigest.reset();
      messageDigest.update(hash);
      messageDigest.update(byteBuffer);
      messageDigest.digest(hash, 0, hash.length);
    } catch (final DigestException e) {
      // This should never happen
      throw new AssertionError(e);
    }
  }

  private void mixKeyAndHash(final byte[] preSharedKey) {
    final byte[][] derivedKeys = noiseHash.deriveKeys(chainingKey, preSharedKey, 3);

    System.arraycopy(derivedKeys[0], 0, chainingKey, 0, derivedKeys[0].length);
    mixHash(derivedKeys[1]);
    cipherState.setKey(derivedKeys[2]);
  }

  private int encryptAndHash(final byte[] plaintext,
                             final int plaintextOffset,
                             final int plaintextLength,
                             final byte[] ciphertext,
                             final int ciphertextOffset) throws ShortBufferException {

    final int ciphertextLength =
        cipherState.encrypt(hash, plaintext, plaintextOffset, plaintextLength, ciphertext, ciphertextOffset);

    mixHash(ciphertext, ciphertextOffset, ciphertextLength);

    return ciphertextLength;
  }

  private int encryptAndHash(final ByteBuffer plaintext, final ByteBuffer ciphertext) throws ShortBufferException {
    final int ciphertextLength = cipherState.encrypt(hash, plaintext, ciphertext);

    mixHash(ciphertext.slice(ciphertext.position() - ciphertextLength, ciphertextLength));

    return ciphertextLength;
  }

  private int decryptAndHash(final byte[] ciphertext,
                             final int ciphertextOffset,
                             final int ciphertextLength,
                             final byte[] plaintext,
                             final int plaintextOffset) throws ShortBufferException, AEADBadTagException {

    final int plaintextLength =
        cipherState.decrypt(hash, ciphertext, ciphertextOffset, ciphertextLength, plaintext, plaintextOffset);

    mixHash(ciphertext, ciphertextOffset, ciphertextLength);

    return plaintextLength;
  }

  private int decryptAndHash(final ByteBuffer ciphertext,
                             final ByteBuffer plaintext) throws ShortBufferException, AEADBadTagException {

    final int initialCiphertextPosition = ciphertext.position();
    final int plaintextLength = cipherState.decrypt(hash, ciphertext, plaintext);

    mixHash(ciphertext.slice(initialCiphertextPosition, ciphertext.position() - initialCiphertextPosition));

    return plaintextLength;
  }

  /**
   * Checks whether this is a handshake for a one-way Noise handshake pattern.
   *
   * @return {@code true} if this is a handshake for a one-way Noise handshake pattern or {@code false} if this is a
   * handshake for an interactive Noise handshake pattern
   */
  public boolean isOneWayHandshake() {
    return handshakePattern.isOneWayPattern();
  }

  /**
   * Checks if this handshake is currently expecting to receive a handshake message from its peer.
   *
   * @return {@code true} if this handshake is expecting to receive a handshake message from its peer as its next action
   * or {@code false} if this handshake is done or is expecting to send a handshake message to its peer as its next
   * action
   *
   * @see #isExpectingWrite()
   * @see #isDone()
   */
  public boolean isExpectingRead() {
    if (hasFallenBack) {
      return false;
    }

    if (currentMessagePattern < handshakePattern.getHandshakeMessagePatterns().length) {
      return handshakePattern.getHandshakeMessagePatterns()[currentMessagePattern].sender() != role;
    }

    // We've completed the whole handshake, so we're not expecting any more messages
    return false;
  }

  /**
   * Checks if this handshake is currently expecting to send a handshake message to its peer.
   *
   * @return {@code true} if this handshake is expecting to send a handshake message to its peer as its next action or
   * {@code false} if this handshake is done or is expecting to receive a handshake message from its peer as its next
   * action
   *
   * @see #isExpectingRead()
   * @see #isDone()
   */
  public boolean isExpectingWrite() {
    if (hasFallenBack) {
      return false;
    }

    if (currentMessagePattern < handshakePattern.getHandshakeMessagePatterns().length) {
      return handshakePattern.getHandshakeMessagePatterns()[currentMessagePattern].sender() == role;
    }

    // We've completed the whole handshake, so we're not expecting any more messages
    return false;
  }

  /**
   * Checks if this handshake has successfully exchanged all messages required by its handshake pattern.
   *
   * @return {@code true} if all required messages have been exchanged or {@code false} if more exchanges are required
   *
   * @see #isExpectingRead()
   * @see #isExpectingWrite()
   */
  public boolean isDone() {
    if (hasFallenBack) {
      return false;
    }

    return currentMessagePattern == handshakePattern.getHandshakeMessagePatterns().length;
  }

  /**
   * Returns the length of the Noise handshake message this handshake would produce for a payload with the given length
   * and with this handshake's current state.
   *
   * @param payloadLength the length of a payload's plaintext
   *
   * @return the length of the message this handshake would produce for a payload with the given length
   *
   * @throws IllegalStateException if this handshake is not currently expecting to send a message to its peer
   */
  public int getOutboundMessageLength(final int payloadLength) {
    if (!isExpectingWrite()) {
      throw new IllegalArgumentException("Handshake is not currently expecting to send a message");
    }

    return getOutboundMessageLength(handshakePattern, currentMessagePattern, keyAgreement.getPublicKeyLength(), payloadLength);
  }

  // Visible for testing
  static int getOutboundMessageLength(final HandshakePattern handshakePattern,
                                      final int message,
                                      final int publicKeyLength,
                                      final int payloadLength) {

    if (message < 0 || message >= handshakePattern.getHandshakeMessagePatterns().length) {
      throw new IndexOutOfBoundsException(
          String.format("Message index must be between 0 and %d for this handshake pattern, but was %d",
              handshakePattern.getHandshakeMessagePatterns().length, message));
    }

    final boolean isPreSharedKeyHandshake = handshakePattern.isPreSharedKeyHandshake();

    // Run through all of this handshake's message patterns to see if we have a key prior to reaching the message of
    // interest
    boolean hasKey = Arrays.stream(handshakePattern.getHandshakeMessagePatterns())
        .limit(message)
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == HandshakePattern.Token.EE
            || token == HandshakePattern.Token.ES
            || token == HandshakePattern.Token.SE
            || token == HandshakePattern.Token.SS
            || token == HandshakePattern.Token.PSK
            || (token == HandshakePattern.Token.E && isPreSharedKeyHandshake));

    int messageLength = 0;

    for (final HandshakePattern.Token token : handshakePattern.getHandshakeMessagePatterns()[message].tokens()) {
      switch (token) {
        case E -> {
          messageLength += publicKeyLength;

          if (isPreSharedKeyHandshake) {
            hasKey = true;
          }
        }
        case S -> {
          messageLength += publicKeyLength;

          if (hasKey) {
            // If we have a key, then the static key is encrypted and has a 16-byte AEAD tag
            messageLength += 16;
          }
        }
        case EE, ES, SE, SS, PSK -> hasKey = true;
      }
    }

    messageLength += payloadLength;

    if (hasKey) {
      // If we have a key, then the payload is encrypted and has a 16-byte AEAD tag
      messageLength += 16;
    }

    return messageLength;
  }

  /**
   * Returns the length of the plaintext of a payload contained in a Noise handshake message of the given length and
   * with this handshake's current state.
   *
   * @param handshakeMessageLength the length of a Noise handshake message received from this party's peer
   *
   * @return the length of the plaintext of a payload contained in a handshake message of the given length
   *
   * @throws IllegalStateException if this handshake is not currently expecting to receive a message from its peer
   * @throws IllegalArgumentException if the given handshake message length shorter than the minimum expected length of
   * an incoming handshake message
   */
  public int getPayloadLength(final int handshakeMessageLength) {
    if (!isExpectingRead()) {
      throw new IllegalStateException("Handshake is not currently expecting to read a message");
    }

    return getPayloadLength(handshakePattern, currentMessagePattern, keyAgreement.getPublicKeyLength(), handshakeMessageLength);
  }

  static int getPayloadLength(final HandshakePattern handshakePattern,
                              final int message,
                              final int publicKeyLength,
                              final int ciphertextLength) {

    final int emptyPayloadMessageLength = getOutboundMessageLength(handshakePattern, message, publicKeyLength, 0);

    if (ciphertextLength < emptyPayloadMessageLength) {
      throw new IllegalArgumentException("Ciphertext is shorter than minimum expected message length");
    }

    return ciphertextLength - emptyPayloadMessageLength;
  }

  /**
   * <p>Writes the next Noise handshake message for this handshake instance, advancing this handshake's internal state.
   * The returned message will include any key material specified by this handshake's current message pattern and either
   * the plaintext or a ciphertext of the given payload.</p>
   *
   * <p>Note that the security properties for the optional payload vary by handshake pattern, message, and sender role.
   * Callers are responsible for verifying that the security properties associated with ny handshake message are
   * suitable for their use case.</p>
   *
   * @param payload the payload to include in this handshake message; may be {@code null}
   *
   * @return a new byte array containing the resulting handshake message
   *
   * @throws IllegalArgumentException if the message produced for the given payload would be larger than the maximum
   * allowed Noise handshake message size
   * @throws IllegalStateException if this handshake is not currently expecting to send a handshake message to its peer
   *
   * @see #isExpectingWrite()
   * @see <a href="https://noiseprotocol.org/noise.html#payload-security-properties">The Noise Protocol Framework - Payload security properties</a>
   */
  public byte[] writeMessage(final byte[] payload) {
    final int payloadLength = payload != null ? payload.length : 0;
    checkOutboundMessageSize(payloadLength);

    final byte[] message = new byte[getOutboundMessageLength(payloadLength)];

    try {
      final int messageLength = writeMessage(payload, 0, payloadLength, message, 0);
      assert message.length == messageLength;
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return message;
  }

  /**
   * <p>Writes the next Noise handshake message for this handshake instance into the given array, advancing this
   * handshake's internal state. The resulting message will include any key material specified by this handshake's
   * current message pattern and either the plaintext or a ciphertext of the given payload.</p>
   *
   * <p>Note that the security properties for the optional payload vary by handshake pattern, message, and sender role.
   * Callers are responsible for verifying that the security properties associated with ny handshake message are
   * suitable for their use case.</p>
   *
   * @param payload a byte array containing the optional payload for this handshake message; may be {@code null}
   * @param payloadOffset the offset within {@code payload} where the payload begins; ignored if {@code payload} is
   * {@code null}
   * @param payloadLength the length of the payload within {@code payload}
   * @param message a byte array into which to write the resulting handshake message
   * @param messageOffset the position within {@code message} at which to begin writing the handshake message
   *
   * @return the number of bytes written to {@code message}
   *
   * @throws IllegalArgumentException if the message produced for the given payload would be larger than the maximum
   * allowed Noise handshake message size
   * @throws IllegalStateException if this handshake is not currently expecting to send a handshake message to its peer
   * @throws ShortBufferException if {@code message} is not large enough (after its offset) to hold the handshake
   * message
   * @see #isExpectingWrite()
   * @see #getOutboundMessageLength(int)
   * @see <a href="https://noiseprotocol.org/noise.html#payload-security-properties">The Noise Protocol Framework -
   * Payload security properties</a>
   */
  public int writeMessage(final byte[] payload,
                          final int payloadOffset,
                          final int payloadLength,
                          final byte[] message,
                          final int messageOffset) throws ShortBufferException {

    checkOutboundMessageSize(payloadLength);

    if (message.length - messageOffset < getOutboundMessageLength(payloadLength)) {
      throw new ShortBufferException("Message array after offset is not large enough to hold handshake message");
    }

    if (!isExpectingWrite()) {
      throw new IllegalStateException("Handshake not currently expecting to write a message");
    }

    int offset = messageOffset;

    final HandshakePattern.MessagePattern messagePattern =
        handshakePattern.getHandshakeMessagePatterns()[currentMessagePattern];

    for (final HandshakePattern.Token token : messagePattern.tokens()) {
      switch (token) {
        case E -> {
          // Ephemeral keys may be specified in advance for "fallback" patterns and for testing, and so may not
          // necessarily be null at this point.
          if (localEphemeralKeyPair == null) {
            localEphemeralKeyPair = keyAgreement.generateKeyPair();
          }

          final byte[] ephemeralKeyBytes = keyAgreement.serializePublicKey(localEphemeralKeyPair.getPublic());
          System.arraycopy(ephemeralKeyBytes, 0, message, offset, keyAgreement.getPublicKeyLength());

          mixHash(ephemeralKeyBytes);

          if (handshakePattern.isPreSharedKeyHandshake()) {
            mixKey(ephemeralKeyBytes);
          }

          offset += keyAgreement.getPublicKeyLength();
        }

        case S -> {
          if (localStaticKeyPair == null) {
            throw new IllegalStateException("No local static public key available");
          }

          try {
            offset += encryptAndHash(keyAgreement.serializePublicKey(localStaticKeyPair.getPublic()), 0, keyAgreement.getPublicKeyLength(),
                message, offset);
          } catch (final ShortBufferException e) {
            // This should never happen for buffers we control
            throw new AssertionError("Short buffer for static key component", e);
          }
        }

        case EE, ES, SE, SS, PSK -> handleMixKeyToken(token);
      }
    }

    if (payload != null) {
      offset += encryptAndHash(payload, payloadOffset, payloadLength, message, offset);
    } else {
      offset += encryptAndHash(EMPTY_BYTE_ARRAY, 0, 0, message, offset);
    }

    currentMessagePattern += 1;

    return offset;
  }

  /**
   * <p>Writes the next Noise handshake message for this handshake instance, advancing this handshake's internal state.
   * The returned message will include any key material specified by this handshake's current message pattern and either
   * the plaintext or a ciphertext of the given payload.</p>
   *
   * <p>Note that the security properties for the optional payload vary by handshake pattern, message, and sender role.
   * Callers are responsible for verifying that the security properties associated with ny handshake message are
   * suitable for their use case.</p>
   *
   * @param payload the payload to include in this handshake message; may be {@code null}
   *
   * @return a new byte buffer containing the resulting handshake message
   *
   * @throws IllegalArgumentException if the message produced for the given payload would be larger than the maximum
   * allowed Noise handshake message size
   * @throws IllegalStateException if this handshake is not currently expecting to send a handshake message to its peer
   *
   * @see #isExpectingWrite()
   * @see <a href="https://noiseprotocol.org/noise.html#payload-security-properties">The Noise Protocol Framework - Payload security properties</a>
   */
  public ByteBuffer writeMessage(final ByteBuffer payload) {
    final int payloadLength = payload != null ? payload.remaining() : 0;
    checkOutboundMessageSize(payloadLength);

    final ByteBuffer message = ByteBuffer.allocate(getOutboundMessageLength(payloadLength));

    try {
      writeMessage(payload, message);
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return message.flip();
  }

  /**
   * <p>Writes the next Noise handshake message for this handshake instance into the given buffer, advancing this
   * handshake's internal state. The resulting message will include any key material specified by this handshake's
   * current message pattern and either the plaintext or a ciphertext of the given payload.</p>
   *
   * <p>Note that the security properties for the optional payload vary by handshake pattern, message, and sender role.
   * Callers are responsible for verifying that the security properties associated with ny handshake message are
   * suitable for their use case.</p>
   *
   * <p>If provided, all {@code payload.remaining()} bytes starting at {@code payload.position()} are processed. Upon
   * return, the payload buffer's position will be equal to its limit; its limit will not have changed. The message
   * buffer's position will have advanced by n, where n is the value returned by this method; the message buffer's limit
   * will not have changed.</p>
   *
   * @param payload a byte buffer containing the optional payload for this handshake message; may be {@code null}
   * @param message a byte buffer into which to write the resulting handshake message
   *
   * @return the number of bytes written to {@code message}
   *
   * @throws IllegalArgumentException if the message produced for the given payload would be larger than the maximum
   * allowed Noise handshake message size
   * @throws IllegalStateException if this handshake is not currently expecting to send a handshake message to its peer
   * @throws ShortBufferException if {@code message} does not have enough remaining capacity to hold the handshake
   * message
   *
   * @see #isExpectingWrite()
   * @see #getOutboundMessageLength(int)
   * @see <a href="https://noiseprotocol.org/noise.html#payload-security-properties">The Noise Protocol Framework -
   * Payload security properties</a>
   */
  public int writeMessage(final ByteBuffer payload,
                          final ByteBuffer message) throws ShortBufferException {

    final int payloadLength = payload != null ? payload.remaining() : 0;
    checkOutboundMessageSize(payloadLength);

    if (message.remaining() < getOutboundMessageLength(payloadLength)) {
      throw new ShortBufferException("Message buffer is not large enough to hold handshake message");
    }

    if (!isExpectingWrite()) {
      throw new IllegalStateException("Handshake not currently expecting to write a message");
    }

    int bytesWritten = 0;

    final HandshakePattern.MessagePattern messagePattern =
        handshakePattern.getHandshakeMessagePatterns()[currentMessagePattern];

    for (final HandshakePattern.Token token : messagePattern.tokens()) {
      switch (token) {
        case E -> {
          // Ephemeral keys may be specified in advance for "fallback" patterns and for testing, and so may not
          // necessarily be null at this point.
          if (localEphemeralKeyPair == null) {
            localEphemeralKeyPair = keyAgreement.generateKeyPair();
          }

          final byte[] ephemeralKeyBytes = keyAgreement.serializePublicKey(localEphemeralKeyPair.getPublic());
          message.put(ephemeralKeyBytes);
          bytesWritten += ephemeralKeyBytes.length;

          mixHash(ephemeralKeyBytes);

          if (handshakePattern.isPreSharedKeyHandshake()) {
            mixKey(ephemeralKeyBytes);
          }
        }

        case S -> {
          if (localStaticKeyPair == null) {
            throw new IllegalStateException("No local static public key available");
          }

          try {
            bytesWritten +=
                encryptAndHash(ByteBuffer.wrap(keyAgreement.serializePublicKey(localStaticKeyPair.getPublic())), message);
          } catch (final ShortBufferException e) {
            // This should never happen for buffers we control
            throw new AssertionError("Short buffer for static key component", e);
          }
        }

        case EE, ES, SE, SS, PSK -> handleMixKeyToken(token);
      }
    }

    bytesWritten += encryptAndHash(Objects.requireNonNullElse(payload, EMPTY_BYTE_BUFFER), message);

    currentMessagePattern += 1;

    return bytesWritten;
  }

  private void checkOutboundMessageSize(final int payloadLength) {
    if (getOutboundMessageLength(payloadLength) > MAX_NOISE_MESSAGE_SIZE) {
      throw new IllegalArgumentException("Message containing payload would be larger than maximum allowed Noise message size");
    }
  }

  /**
   * Reads the next handshake message, advancing this handshake's internal state.
   *
   * @param message the handshake message to read
   *
   * @return a byte array containing the plaintext of the payload included in the handshake message; may be empty
   *
   * @throws AEADBadTagException if the AEAD tag for any encrypted component of the given handshake message does not
   * match the calculated value
   * @throws IllegalArgumentException if the given message is too short to contain the expected handshake message or if
   * the given message is larger than the maximum allowed Noise handshake message size
   */
  public byte[] readMessage(final byte[] message) throws AEADBadTagException {
    checkInboundMessageSize(message.length);

    final byte[] payload = new byte[getPayloadLength(message.length)];

    try {
      final int payloadLength = readMessage(message, 0, message.length, payload, 0);
      assert payload.length == payloadLength;
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return payload;
  }

  /**
   * Reads the next handshake message, writing the plaintext of the message's payload into the given array and advancing
   * this handshake's internal state.
   *
   * @param message a byte array containing the handshake message to read
   * @param messageOffset the position within {@code message} at which the handshake message begins
   * @param messageLength the length of the handshake message within {@code message}
   * @param payload a byte array into which to write the plaintext of the payload included in the given handshake
   * message
   * @param payloadOffset the position within {@code payload} at which to begin writing the payload
   *
   * @return a byte array containing the plaintext of the payload included in the handshake message; may be empty
   *
   * @throws AEADBadTagException if the AEAD tag for any encrypted component of the given handshake message does not
   * match the calculated value
   * @throws ShortBufferException if {@code payload} is too short (after its offset) to hold the plaintext of the
   * payload included in the given handshake message
   * @throws IllegalArgumentException if the given message is too short to contain the expected handshake message or if
   * the given message is larger than the maximum allowed Noise handshake message size
   *
   * @see #getPayloadLength(int)
   */
  public int readMessage(final byte[] message,
                         final int messageOffset,
                         final int messageLength,
                         final byte[] payload,
                         final int payloadOffset) throws ShortBufferException, AEADBadTagException {

    checkInboundMessageSize(messageLength);

    if (payload.length - payloadOffset < getPayloadLength(messageLength)) {
      throw new ShortBufferException("Payload array after offset is not large enough to hold payload");
    }

    if (!isExpectingRead()) {
      throw new IllegalStateException("Handshake not currently expecting to read a message");
    }

    int offset = messageOffset;

    final HandshakePattern.MessagePattern messagePattern =
        handshakePattern.getHandshakeMessagePatterns()[currentMessagePattern];

    for (final HandshakePattern.Token token : messagePattern.tokens()) {
      switch (token) {
        case E -> {
          if (remoteEphemeralPublicKey != null) {
            throw new IllegalStateException("Remote ephemeral key already set");
          }

          final byte[] ephemeralKeyBytes = new byte[keyAgreement.getPublicKeyLength()];
          System.arraycopy(message, offset, ephemeralKeyBytes, 0, ephemeralKeyBytes.length);

          remoteEphemeralPublicKey = keyAgreement.deserializePublicKey(ephemeralKeyBytes);

          mixHash(ephemeralKeyBytes);

          if (handshakePattern.isPreSharedKeyHandshake()) {
            mixKey(ephemeralKeyBytes);
          }

          offset += ephemeralKeyBytes.length;
        }

        case S -> {
          if (remoteStaticPublicKey != null) {
            throw new IllegalStateException("Remote static key already set");
          }

          final int staticKeyCiphertextLength = keyAgreement.getPublicKeyLength() + (cipherState.hasKey() ? 16 : 0);
          final byte[] staticKeyBytes = new byte[keyAgreement.getPublicKeyLength()];

          decryptAndHash(message, offset, staticKeyCiphertextLength, staticKeyBytes, 0);

          remoteStaticPublicKey = keyAgreement.deserializePublicKey(staticKeyBytes);

          offset += staticKeyCiphertextLength;
        }

        case EE, ES, SE, SS, PSK -> handleMixKeyToken(token);
      }
    }

    currentMessagePattern += 1;

    return decryptAndHash(message, offset, messageLength - offset, payload, payloadOffset);
  }

  /**
   * Reads the next handshake message, advancing this handshake's internal state.
   *
   * @param message the handshake message to read
   *
   * @return a new byte buffer containing the plaintext of the payload included in the handshake message; may be empty
   *
   * @throws AEADBadTagException if the AEAD tag for any encrypted component of the given handshake message does not
   * match the calculated value
   * @throws IllegalArgumentException if the given message is too short to contain the expected handshake message or if
   * the given message is larger than the maximum allowed Noise handshake message size
   */
  public ByteBuffer readMessage(final ByteBuffer message) throws AEADBadTagException {
    checkInboundMessageSize(message.remaining());

    final ByteBuffer payload = ByteBuffer.allocate(getPayloadLength(message.remaining()));

    try {
      readMessage(message, payload);
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return payload.flip();
  }

  /**
   * <p>Reads the next handshake message, writing the plaintext of the message's payload into the given buffer and
   * advancing this handshake's internal state.</p>
   *
   * <p>All {@code message.remaining()} bytes starting at {@code message.position()} are processed. Upon return,
   * the message buffer's position will be equal to its limit; its limit will not have changed. The payload buffer's
   * position will have advanced by n, where n is the value returned by this method; the payload buffer's limit will not
   * have changed.</p>
   *
   * @param message a byte buffer containing the handshake message to read
   * @param payload a byte buffer into which to write the plaintext of the payload included in the given handshake
   * message
   *
   * @return the number of bytes written to {@code payload}
   *
   * @throws AEADBadTagException if the AEAD tag for any encrypted component of the given handshake message does not
   * match the calculated value
   * @throws ShortBufferException if {@code payload} does not have enough remaining capacity to hold the plaintext of
   * the payload included in the given handshake message
   * @throws IllegalArgumentException if the given message is too short to contain the expected handshake message or if
   * the given message is larger than the maximum allowed Noise handshake message size
   *
   * @see #getPayloadLength(int)
   */
  public int readMessage(final ByteBuffer message,
                         final ByteBuffer payload) throws ShortBufferException, AEADBadTagException {

    checkInboundMessageSize(message.remaining());

    if (payload.remaining() < getPayloadLength(message.remaining())) {
      throw new ShortBufferException("Payload buffer is not large enough to hold payload");
    }

    if (!isExpectingRead()) {
      throw new IllegalStateException("Handshake not currently expecting to read a message");
    }

    final HandshakePattern.MessagePattern messagePattern =
        handshakePattern.getHandshakeMessagePatterns()[currentMessagePattern];

    for (final HandshakePattern.Token token : messagePattern.tokens()) {
      switch (token) {
        case E -> {
          if (remoteEphemeralPublicKey != null) {
            throw new IllegalStateException("Remote ephemeral key already set");
          }

          final byte[] ephemeralKeyBytes = new byte[keyAgreement.getPublicKeyLength()];
          message.get(ephemeralKeyBytes);

          remoteEphemeralPublicKey = keyAgreement.deserializePublicKey(ephemeralKeyBytes);

          mixHash(ephemeralKeyBytes);

          if (handshakePattern.isPreSharedKeyHandshake()) {
            mixKey(ephemeralKeyBytes);
          }
        }

        case S -> {
          if (remoteStaticPublicKey != null) {
            throw new IllegalStateException("Remote static key already set");
          }

          final int staticKeyCiphertextLength = keyAgreement.getPublicKeyLength() + (cipherState.hasKey() ? 16 : 0);
          final byte[] staticKeyBytes = new byte[keyAgreement.getPublicKeyLength()];

          final ByteBuffer staticKeyCiphertextSlice = message.slice(message.position(), staticKeyCiphertextLength);
          decryptAndHash(staticKeyCiphertextSlice, ByteBuffer.wrap(staticKeyBytes));

          // Operating on a slice doesn't advance the main buffer's position; do so manually instead
          message.position(message.position() + staticKeyCiphertextLength);

          remoteStaticPublicKey = keyAgreement.deserializePublicKey(staticKeyBytes);
        }

        case EE, ES, SE, SS, PSK -> handleMixKeyToken(token);
      }
    }

    currentMessagePattern += 1;

    return decryptAndHash(message, payload);
  }

  private void checkInboundMessageSize(final int messageSize) {
    if (messageSize > MAX_NOISE_MESSAGE_SIZE) {
      throw new IllegalArgumentException("Message is larger than maximum allowed Noise message size");
    }
  }

  private void handleMixKeyToken(final HandshakePattern.Token token) {
    switch (token) {
      case EE -> {
        if (localEphemeralKeyPair == null) {
          throw new IllegalStateException("No local ephemeral key available");
        }

        if (remoteEphemeralPublicKey == null) {
          throw new IllegalStateException("No remote ephemeral key available");
        }

        mixKey(keyAgreement.generateSecret(localEphemeralKeyPair.getPrivate(), remoteEphemeralPublicKey));
      }

      case ES -> {
        switch (role) {
          case INITIATOR -> {
            if (localEphemeralKeyPair == null) {
              throw new IllegalStateException("No local ephemeral key available");
            }

            if (remoteStaticPublicKey == null) {
              throw new IllegalStateException("No remote static key available");
            }

            mixKey(keyAgreement.generateSecret(localEphemeralKeyPair.getPrivate(), remoteStaticPublicKey));
          }
          case RESPONDER -> {
            if (localStaticKeyPair == null) {
              throw new IllegalStateException("No local static key available");
            }

            if (remoteEphemeralPublicKey == null) {
              throw new IllegalStateException("No remote ephemeral key available");
            }

            mixKey(keyAgreement.generateSecret(localStaticKeyPair.getPrivate(), remoteEphemeralPublicKey));
          }
        }
      }

      case SE -> {
        switch (role) {
          case INITIATOR -> {
            if (localStaticKeyPair == null) {
              throw new IllegalStateException("No local static key available");
            }

            if (remoteEphemeralPublicKey == null) {
              throw new IllegalStateException("No remote ephemeral key available");
            }

            mixKey(keyAgreement.generateSecret(localStaticKeyPair.getPrivate(), remoteEphemeralPublicKey));
          }
          case RESPONDER -> {
            if (localEphemeralKeyPair == null) {
              throw new IllegalStateException("No local ephemeral key available");
            }

            if (remoteStaticPublicKey == null) {
              throw new IllegalStateException("No remote static key available");
            }

            mixKey(keyAgreement.generateSecret(localEphemeralKeyPair.getPrivate(), remoteStaticPublicKey));
          }
        }
      }

      case SS -> {
        if (localStaticKeyPair == null) {
          throw new IllegalStateException("No local static key available");
        }

        if (remoteStaticPublicKey == null) {
          throw new IllegalStateException("No remote static key available");
        }

        mixKey(keyAgreement.generateSecret(localStaticKeyPair.getPrivate(), remoteStaticPublicKey));
      }

      case PSK -> {
        if (preSharedKeys == null || currentPreSharedKey >= preSharedKeys.size()) {
          throw new IllegalStateException("No pre-shared key available");
        }

        mixKeyAndHash(preSharedKeys.get(currentPreSharedKey++));
      }

      default -> throw new IllegalArgumentException("Unexpected key-mixing token: " + token.name());
    }
  }

  /**
   * "Falls back" to the named handshake pattern, transferring any appropriate static/ephemeral keys and an empty
   * collection of pre-shared keys.
   *
   * @param handshakePatternName the name of the handshake pattern to which to fall back; must be a pattern with a
   *                             "fallback" modifier
   *
   * @return a new Noise handshake instance that implements the given fallback handshake pattern
   *
   * @throws NoSuchPatternException if the given fallback pattern name is not a recognized Noise handshake pattern name
   * or cannot be derived from a recognized Noise handshake pattern
   * @throws IllegalArgumentException if the given fallback pattern name is not a fallback pattern
   * @throws IllegalStateException if the given fallback pattern requires key material not available to the current
   * handshake
   *
   * @see <a href="https://noiseprotocol.org/noise.html#the-fallback-modifier">The Noise Protocol Framework - The fallback modifier</a>
   *
   * @see HandshakePattern#isFallbackPattern()
   */
  public NoiseHandshake fallbackTo(final String handshakePatternName) throws NoSuchPatternException {
    return fallbackTo(handshakePatternName, null);
  }

  /**
   * "Falls back" to the named handshake pattern, transferring any appropriate static/ephemeral keys and the given
   * collection of pre-shared keys.
   *
   * @param handshakePatternName the name of the handshake pattern to which to fall back; must be a pattern with a
   *                             "fallback" modifier
   * @param preSharedKeys the pre-shared keys to use in the fallback handshake; may be {@code null}
   *
   * @return a new Noise handshake instance that implements the given fallback handshake pattern
   *
   * @throws NoSuchPatternException if the given fallback pattern name is not a recognized Noise handshake pattern name
   * or cannot be derived from a recognized Noise handshake pattern
   * @throws IllegalArgumentException if the given fallback pattern name is not a fallback pattern
   * @throws IllegalStateException if the given fallback pattern requires key material not available to the current
   * handshake
   *
   * @see <a href="https://noiseprotocol.org/noise.html#the-fallback-modifier">The Noise Protocol Framework - The fallback modifier</a>
   *
   * @see HandshakePattern#isFallbackPattern()
   */
  public NoiseHandshake fallbackTo(final String handshakePatternName, final List<byte[]> preSharedKeys) throws NoSuchPatternException {
    if (hasFallenBack) {
      throw new IllegalStateException("Handshake has already fallen back to another pattern");
    }

    final HandshakePattern fallbackPattern = HandshakePattern.getInstance(handshakePatternName);

    if (!fallbackPattern.isFallbackPattern()) {
      throw new IllegalArgumentException(handshakePatternName + " is not a valid fallback pattern name");
    }

    final KeyPair fallbackLocalStaticKeyPair;

    if (fallbackPattern.requiresLocalStaticKeyPair(role)) {
      if (localStaticKeyPair != null) {
        fallbackLocalStaticKeyPair = localStaticKeyPair;
      } else {
        throw new IllegalStateException("Fallback pattern requires a local static key pair, but none is available");
      }
    } else {
      fallbackLocalStaticKeyPair = null;
    }

    final PublicKey fallbackRemoteStaticPublicKey;

    if (fallbackPattern.requiresRemoteStaticPublicKey(role)) {
      if (remoteStaticPublicKey != null) {
        fallbackRemoteStaticPublicKey = remoteStaticPublicKey;
      } else {
        throw new IllegalStateException("Fallback pattern requires a remote static public key, but none is available");
      }
    } else {
      fallbackRemoteStaticPublicKey = null;
    }

    final PublicKey fallbackRemoteEphemeralPublicKey;

    if (fallbackPattern.requiresRemoteEphemeralPublicKey(role)) {
      if (remoteEphemeralPublicKey != null) {
        fallbackRemoteEphemeralPublicKey = remoteEphemeralPublicKey;
      } else {
        throw new IllegalStateException("Fallback pattern requires a remote ephemeral public key, but none is available");
      }
    } else {
      fallbackRemoteEphemeralPublicKey = null;
    }

    hasFallenBack = true;

    return new NoiseHandshake(role,
        fallbackPattern,
        keyAgreement,
        cipherState.getCipher(),
        noiseHash,
        prologue,
        fallbackLocalStaticKeyPair,
        localEphemeralKeyPair,
        fallbackRemoteStaticPublicKey,
        fallbackRemoteEphemeralPublicKey,
        preSharedKeys);
  }

  /**
   * Builds an interactive Noise transport object from this handshake. This method may be called exactly once, only if
   * this is an interactive (i.e. not one-way) handshake, and only when the handshake is done.
   *
   * @return an interactive Noise transport object derived from this completed handshake
   *
   * @throws IllegalStateException if this is a one-way handshake, the handshake has not finished, or this handshake has
   * previously been "split" into a Noise transport object
   *
   * @see #isDone()
   * @see #isOneWayHandshake()
   */
  public NoiseTransport toTransport() {
    if (handshakePattern.isOneWayPattern()) {
      throw new IllegalStateException("Cannot split a handshake for a one-way pattern into an interactive transport instance");
    }

    return split();
  }

  /**
   * Builds a read-only Noise transport object from this handshake. This method may be called exactly once, only if
   * this is a one-way handshake, only if this is the handshake for the responder, and only when the handshake is done.
   *
   * @return a read-only Noise transport object derived from this completed handshake
   *
   * @throws IllegalStateException if this is not a one-way handshake, if this method is called on the initiator side
   * of a one-way handshake, if the handshake has not finished, or this handshake has previously been "split" into a
   * Noise transport object
   *
   * @see #isDone()
   * @see #isOneWayHandshake()
   */
  public NoiseTransportReader toTransportReader() {
    if (!handshakePattern.isOneWayPattern()) {
      throw new IllegalStateException("Interactive handshakes may not be split into one-way transport objects");
    }

    if (role != Role.RESPONDER) {
      throw new IllegalStateException("Read-only transport objects may only be created for responders in one-way handshakes");
    }

    return split();
  }

  /**
   * Builds a write-only Noise transport object from this handshake. This method may be called exactly once, only if
   * this is a one-way handshake, only if this is the handshake for the initiator, and only when the handshake is done.
   *
   * @return a read-only Noise transport object derived from this completed handshake
   *
   * @throws IllegalStateException if this is not a one-way handshake, if this method is called on the responder side
   * of a one-way handshake, if the handshake has not finished, or this handshake has previously been "split" into a
   * Noise transport object
   *
   * @see #isDone()
   * @see #isOneWayHandshake()
   */
  public NoiseTransportWriter toTransportWriter() {
    if (!handshakePattern.isOneWayPattern()) {
      throw new IllegalStateException("Interactive handshakes may not be split into one-way transport objects");
    }

    if (role != Role.INITIATOR) {
      throw new IllegalStateException("Write-only transport objects may only be created for initiators in one-way handshakes");
    }

    return split();
  }

  private NoiseTransportImpl split() {
    if (!isDone()) {
      throw new IllegalStateException("Handshake is not finished and expects to exchange more messages");
    }

    if (hasSplit) {
      throw new IllegalStateException("Handshake has already been split into a Noise transport instance");
    }

    final byte[][] derivedKeys = noiseHash.deriveKeys(chainingKey, EMPTY_BYTE_ARRAY, 2);

    // We switch to "Bob-initiated" mode in fallback patterns
    final boolean isEffectiveInitiator =
        handshakePattern.isFallbackPattern() ? role == Role.RESPONDER : role == Role.INITIATOR;

    final CipherState readerCipherState = new CipherState(cipherState.getCipher());
    readerCipherState.setKey(derivedKeys[isEffectiveInitiator ? 1 : 0]);

    final CipherState writerCipherState = new CipherState(cipherState.getCipher());
    writerCipherState.setKey(derivedKeys[isEffectiveInitiator ? 0 : 1]);

    hasSplit = true;

    return new NoiseTransportImpl(readerCipherState, writerCipherState);
  }

  /**
   * Returns a hash of this handshake's state that uniquely identifies the Noise session. May only be called once the
   * handshake has been transformed into a transport instance.
   *
   * @return a hash of this handshake's state that uniquely identifies the Noise session
   *
   * @throws IllegalStateException if this handshake instance has not yet be transformed into a transport instance
   *
   * @see <a href="https://noiseprotocol.org/noise.html#channel-binding">The Noise Protocol Framework - Channel binding</a>
   *
   * @see #toTransport()
   * @see #toTransportReader()
   * @see #toTransportWriter()
   */
  public byte[] getHash() {
    if (!hasSplit) {
      throw new IllegalStateException("Cannot retrieve a handshake hash until handshake has been split into a transport instance");
    }

    return hash;
  }

    public PublicKey getRemoteStaticPublicKey() {
        return remoteStaticPublicKey;
    }

    /**
     * Get the remote ephemeral public key.
     * Used for THP credential matching.
     *
     * @return The remote ephemeral public key
     */
    public PublicKey getRemoteEphemeralPublicKey() {
        return remoteEphemeralPublicKey;
    }

    /**
     * Set the local static key pair.
     * Used for THP credential matching where the host key must be updated mid-handshake.
     *
     * @param keyPair The new local static key pair
     */
    public void setLocalStaticKeyPair(final KeyPair keyPair) {
        this.localStaticKeyPair = keyPair;
    }
}
