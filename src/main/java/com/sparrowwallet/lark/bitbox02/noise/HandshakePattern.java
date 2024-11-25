package com.sparrowwallet.lark.bitbox02.noise;

import javax.annotation.Nullable;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A handshake pattern specifies the sequential exchange of messages that comprise a Noise handshake. Callers generally
 * do not need to interact directly with handshake patterns.
 */
class HandshakePattern {

  private final String name;

  private final MessagePattern[] preMessagePatterns;
  private final MessagePattern[] handshakeMessagePatterns;

  private static final Map<String, HandshakePattern> FUNDAMENTAL_PATTERNS_BY_NAME;

  static {
    FUNDAMENTAL_PATTERNS_BY_NAME = Stream.of(
            """
                N:
                  <- s
                  ...
                  -> e, es
                """,

            """
                K:
                  -> s
                  <- s
                  ...
                  -> e, es, ss
                """,

            """
                X:
                  <- s
                  ...
                  -> e, es, s, ss
                """,

            """
                NN:
                  -> e
                  <- e, ee
                """,

            """
                KN:
                  -> s
                  ...
                  -> e
                  <- e, ee, se
                """,

            """
                NK:
                  <- s
                  ...
                  -> e, es
                  <- e, ee
                """,

            """
                KK:
                  -> s
                  <- s
                  ...
                  -> e, es, ss
                  <- e, ee, se
                """,

            """
                NX:
                  -> e
                  <- e, ee, s, es
                """,

            """
                KX:
                  -> s
                  ...
                  -> e
                  <- e, ee, se, s, es
                """,

            """
                XN:
                  -> e
                  <- e, ee
                  -> s, se
                """,

            """
                IN:
                  -> e, s
                  <- e, ee, se
                """,

            """
                XK:
                  <- s
                  ...
                  -> e, es
                  <- e, ee
                  -> s, se
                """,

            """
                IK:
                  <- s
                  ...
                  -> e, es, s, ss
                  <- e, ee, se
                """,

            """
                XX:
                  -> e
                  <- e, ee, s, es
                  -> s, se
                """,

            """
                IX:
                  -> e, s
                  <- e, ee, se, s, es
                """,

            """
                NK1:
                  <- s
                  ...
                  -> e
                  <- e, ee, es
                """,

            """
                NX1:
                  -> e
                  <- e, ee, s
                  -> es
                """,

            """
                X1N:
                  -> e
                  <- e, ee
                  -> s
                  <- se
                """,

            """
                X1K:
                  <- s
                  ...
                  -> e, es
                  <- e, ee
                  -> s
                  <- se
                """,

            """
                XK1:
                  <- s
                  ...
                  -> e
                  <- e, ee, es
                  -> s, se
                """,

            """
                X1K1:
                  <- s
                  ...
                  -> e
                  <- e, ee, es
                  -> s
                  <- se
                """,

            """
                X1X:
                  -> e
                  <- e, ee, s, es
                  -> s
                  <- se
                """,

            """
                XX1:
                  -> e
                  <- e, ee, s
                  -> es, s, se
                """,

            """
                X1X1:
                  -> e
                  <- e, ee, s
                  -> es, s
                  <- se
                """,

            """
                K1N:
                  -> s
                  ...
                  -> e
                  <- e, ee
                  -> se
                """,

            """
                K1K:
                  -> s
                  <- s
                  ...
                  -> e, es
                  <- e, ee
                  -> se
                """,

            """
                KK1:
                  -> s
                  <- s
                  ...
                  -> e
                  <- e, ee, se, es
                """,

            """
                K1K1:
                  -> s
                  <- s
                  ...
                  -> e
                  <- e, ee, es
                  -> se
                """,

            """
                K1X:
                  -> s
                  ...
                  -> e
                  <- e, ee, s, es
                  -> se
                """,

            """
                KX1:
                  -> s
                  ...
                  -> e
                  <- e, ee, se, s
                  -> es
                """,

            """
                K1X1:
                  -> s
                  ...
                  -> e
                  <- e, ee, s
                  -> se, es
                """,

            """
                I1N:
                  -> e, s
                  <- e, ee
                  -> se
                """,

            """
                I1K:
                  <- s
                  ...
                  -> e, es, s
                  <- e, ee
                  -> se
                """,

            """
                IK1:
                  <- s
                  ...
                  -> e, s
                  <- e, ee, se, es
                """,

            """
                I1K1:
                  <- s
                  ...
                  -> e, s
                  <- e, ee, es
                  -> se
                """,

            """
                I1X:
                  -> e, s
                  <- e, ee, s, es
                  -> se
                """,

            """
                IX1:
                  -> e, s
                  <- e, ee, se, s
                  -> es
                """,

            """
                I1X1:
                  -> e, s
                  <- e, ee, s
                  -> se, es
                """)
        .map(HandshakePattern::fromString)
        .collect(Collectors.toMap(HandshakePattern::getName, handshakePattern -> handshakePattern));
  }

  private static final Map<String, HandshakePattern> DERIVED_PATTERNS_BY_NAME = new ConcurrentHashMap<>();

  private static final String PRE_MESSAGE_SEPARATOR = "...";

  HandshakePattern(final String name, final MessagePattern[] preMessagePatterns, final MessagePattern[] handshakeMessagePatterns) {
    this.name = name;

    this.preMessagePatterns = preMessagePatterns;
    this.handshakeMessagePatterns = handshakeMessagePatterns;
  }

  record MessagePattern(NoiseHandshake.Role sender, Token[] tokens) {
    @Override
    public String toString() {
      final String prefix = switch (sender()) {
        case INITIATOR -> "  -> ";
        case RESPONDER -> "  <- ";
      };

      return prefix + Arrays.stream(tokens())
          .map(token -> token.name().toLowerCase())
          .collect(Collectors.joining(", "));
    }

    @Override
    public boolean equals(final Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      final MessagePattern that = (MessagePattern) o;
      return sender == that.sender && Arrays.equals(tokens, that.tokens);
    }

    @Override
    public int hashCode() {
      int result = Objects.hash(sender);
      result = 31 * result + Arrays.hashCode(tokens);
      return result;
    }
  }

  enum Token {
    E,
    S,
    EE,
    ES,
    SE,
    SS,
    PSK;

    static Token fromString(final String string) {
      return switch (string) {
        case "e", "E" -> E;
        case "s", "S" -> S;
        case "ee", "EE" -> EE;
        case "es", "ES" -> ES;
        case "se", "SE" -> SE;
        case "ss", "SS" -> SS;
        case "psk", "PSK" -> PSK;
        default -> throw new IllegalArgumentException("Unrecognized token: " + string);
      };
    }
  }

  /**
   * Returns the name of this handshake pattern.
   *
   * @return the name of this handshake pattern
   */
  String getName() {
    return name;
  }

  MessagePattern[] getPreMessagePatterns() {
    return preMessagePatterns;
  }

  MessagePattern[] getHandshakeMessagePatterns() {
    return handshakeMessagePatterns;
  }

  /**
   * Returns a {@code HandshakePattern} instance for the handshake pattern with the given name.
   *
   * @param name the name of the handshake pattern for which to retrieve a {@code HandshakePattern} instance
   *
   * @return a {@code HandshakePattern} instance for the given handshake pattern name
   *
   * @throws NoSuchPatternException if the given cannot be resolved to a Noise handshake pattern
   */
  static HandshakePattern getInstance(final String name) throws NoSuchPatternException {
    if (FUNDAMENTAL_PATTERNS_BY_NAME.containsKey(name)) {
      return FUNDAMENTAL_PATTERNS_BY_NAME.get(name);
    }

    @Nullable final HandshakePattern derivedPattern = DERIVED_PATTERNS_BY_NAME.computeIfAbsent(name, n -> {
      try {
        final String fundamentalPatternName = getFundamentalPatternName(name);

        @Nullable HandshakePattern handshakePattern;

        if (FUNDAMENTAL_PATTERNS_BY_NAME.containsKey(fundamentalPatternName)) {
          handshakePattern = FUNDAMENTAL_PATTERNS_BY_NAME.get(fundamentalPatternName);

          for (final String modifier : getModifiers(name)) {
            handshakePattern = handshakePattern.withModifier(modifier);
          }
        } else {
          handshakePattern = null;
        }

        return handshakePattern;
      } catch (final IllegalArgumentException e) {
        return null;
      }
    });

    if (derivedPattern != null) {
      return derivedPattern;
    }

    throw new NoSuchPatternException(name);
  }

  static String getFundamentalPatternName(final String fullPatternName) {
    final int fundamentalPatternLength = Math.toIntExact(fullPatternName.chars()
        .takeWhile(c -> c == 'N' || c == 'K' || c == 'X' || c == 'I' || c == '1')
        .count());

    if (fundamentalPatternLength == fullPatternName.length()) {
      return fullPatternName;
    } else if (fundamentalPatternLength > 0) {
      return fullPatternName.substring(0, fundamentalPatternLength);
    }

    throw new IllegalArgumentException("Invalid Noise pattern name: " + fullPatternName);
  }

  static List<String> getModifiers(final String fullPatternName) {
    final String fundamentalPatternName = getFundamentalPatternName(fullPatternName);

    if (fullPatternName.length() == fundamentalPatternName.length()) {
      return Collections.emptyList();
    }

    return Arrays.asList(fullPatternName.substring(fundamentalPatternName.length()).split("\\+"));
  }

  HandshakePattern withModifier(final String modifier) {
    final MessagePattern[][] modifiedMessagePatterns;

    if ("fallback".equals(modifier)) {
      modifiedMessagePatterns = getPatternsWithFallbackModifier();
    } else if (modifier.startsWith("psk")) {
      modifiedMessagePatterns = getPatternsWithPskModifier(modifier);
    } else {
      throw new IllegalArgumentException("Unrecognized modifier: " + modifier);
    }

    assert modifiedMessagePatterns.length == 2;

    return new HandshakePattern(getModifiedName(modifier), modifiedMessagePatterns[0], modifiedMessagePatterns[1]);
  }

  private MessagePattern[][] getPatternsWithFallbackModifier() {
    if (!isValidFallbackMessagePattern(handshakeMessagePatterns[0])) {
      throw new IllegalStateException("Cannot generate fallback pattern; first message pattern is not a fallback-eligible message pattern");
    }

    final MessagePattern[] modifiedPreMessagePatterns = new MessagePattern[getPreMessagePatterns().length + 1];
    final MessagePattern[] modifiedHandshakeMessagePatterns =
        new MessagePattern[getHandshakeMessagePatterns().length - 1];

    System.arraycopy(getPreMessagePatterns(), 0, modifiedPreMessagePatterns, 0, getPreMessagePatterns().length);
    modifiedPreMessagePatterns[modifiedPreMessagePatterns.length - 1] = getHandshakeMessagePatterns()[0];

    System.arraycopy(getHandshakeMessagePatterns(), 1, modifiedHandshakeMessagePatterns,
        0, getHandshakeMessagePatterns().length - 1);

    return new MessagePattern[][] { modifiedPreMessagePatterns, modifiedHandshakeMessagePatterns };
  }

  private MessagePattern[][] getPatternsWithPskModifier(final String modifier) {
    final int pskIndex = Integer.parseInt(modifier.substring("psk".length()));

    final MessagePattern[] modifiedPreMessagePatterns = getPreMessagePatterns().clone();
    final MessagePattern[] modifiedHandshakeMessagePatterns = getHandshakeMessagePatterns().clone();

    if (pskIndex == 0) {
      // Insert a PSK token at the start of the first message
      final Token[] originalTokens = modifiedHandshakeMessagePatterns[0].tokens();
      final Token[] modifiedTokens = new Token[originalTokens.length + 1];
      modifiedTokens[0] = Token.PSK;
      System.arraycopy(originalTokens, 0, modifiedTokens, 1, originalTokens.length);

      modifiedHandshakeMessagePatterns[0] =
          new MessagePattern(modifiedHandshakeMessagePatterns[0].sender, modifiedTokens);
    } else {
      // Insert a PSK at the end of the N-1st message
      final Token[] originalTokens = modifiedHandshakeMessagePatterns[pskIndex - 1].tokens();
      final Token[] modifiedTokens = new Token[originalTokens.length + 1];
      modifiedTokens[modifiedTokens.length - 1] = Token.PSK;
      System.arraycopy(originalTokens, 0, modifiedTokens, 0, originalTokens.length);

      modifiedHandshakeMessagePatterns[pskIndex - 1] =
          new MessagePattern(modifiedHandshakeMessagePatterns[pskIndex - 1].sender, modifiedTokens);
    }

    return new MessagePattern[][] { modifiedPreMessagePatterns, modifiedHandshakeMessagePatterns };
  }

  private String getModifiedName(final String modifier) {
    final String modifiedName;

    if (getName().equals(getFundamentalPatternName(getName()))) {
      // Our current name doesn't have any modifiers, and so this is the first
      modifiedName = getName() + modifier;
    } else {
      modifiedName = getName() + "+" + modifier;
    }

    return modifiedName;
  }

  static boolean isValidFallbackMessagePattern(final MessagePattern messagePattern) {
    if (messagePattern.sender() != NoiseHandshake.Role.INITIATOR) {
      return false;
    }

    if (messagePattern.tokens().length == 1) {
      return messagePattern.tokens()[0] == Token.E || messagePattern.tokens()[0] == Token.S;
    } else if (messagePattern.tokens().length == 2) {
      return messagePattern.tokens()[0] == Token.E && messagePattern.tokens()[1] == Token.S;
    }

    return false;
  }

  static HandshakePattern fromString(final String patternString) {
    final String name = patternString.lines()
        .findFirst()
        .filter(line -> line.endsWith(":"))
        .map(line -> line.substring(0, line.length() - 1))
        .orElseThrow(() -> new IllegalArgumentException("Pattern string did not begin with a name line"));

    final boolean hasPreMessages = patternString.lines()
        .map(String::trim)
        .anyMatch(PRE_MESSAGE_SEPARATOR::equals);

    final MessagePattern[] preMessagePatterns;
    final MessagePattern[] messagePatterns;

    if (hasPreMessages) {
      preMessagePatterns = patternString.lines()
          // Skip the name line
          .skip(1)
          .map(String::trim)
          .takeWhile(line -> !PRE_MESSAGE_SEPARATOR.equals(line))
          .map(HandshakePattern::messagePatternFromString)
          .toList()
          .toArray(new MessagePattern[0]);

      messagePatterns = patternString.lines()
          // Skip the name line
          .skip(1)
          .map(String::trim)
          .dropWhile(line -> !PRE_MESSAGE_SEPARATOR.equals(line))
          // Skip the separator itself
          .skip(1)
          .map(HandshakePattern::messagePatternFromString)
          .toList()
          .toArray(new MessagePattern[0]);

    } else {
      preMessagePatterns = new MessagePattern[0];

      messagePatterns = patternString.lines()
          // Skip the name line
          .skip(1)
          .map(String::trim)
          .map(HandshakePattern::messagePatternFromString)
          .toList()
          .toArray(new MessagePattern[0]);
    }

    return new HandshakePattern(name, preMessagePatterns, messagePatterns);
  }

  private static MessagePattern messagePatternFromString(final String messagePatternString) {
    final NoiseHandshake.Role sender;

    if (messagePatternString.startsWith("-> ")) {
      sender = NoiseHandshake.Role.INITIATOR;
    } else if (messagePatternString.startsWith("<- ")) {
      sender = NoiseHandshake.Role.RESPONDER;
    } else {
      throw new IllegalArgumentException("Could not identify sender");
    }

    final Token[] tokens = Arrays.stream(messagePatternString.substring(3).split(","))
        .map(String::trim)
        .map(Token::fromString)
        .toList()
        .toArray(new Token[0]);

    return new MessagePattern(sender, tokens);
  }

  /**
   * Checks whether this is a one-way handshake pattern.
   *
   * @return {@code true} if this is a one-way handshake pattern or {@code false} if it is an interactive handshake
   * pattern
   *
   * @see <a href="https://noiseprotocol.org/noise.html#one-way-handshake-patterns">The Noise Protocol Framework - One-way handshake patterns</a>
   */
  boolean isOneWayPattern() {
    return Arrays.stream(getHandshakeMessagePatterns())
        .allMatch(messagePattern -> messagePattern.sender() == NoiseHandshake.Role.INITIATOR);
  }

  boolean isFallbackPattern() {
    return getModifiers(getName()).contains("fallback");
  }

  boolean isPreSharedKeyHandshake() {
    return Arrays.stream(getHandshakeMessagePatterns())
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == Token.PSK);
  }

  /**
   * Returns the number of pre-shared keys either party in this handshake must provide prior to beginning the handshake.
   *
   * @return the number of pre-shared keys either party in this handshake must provide prior to beginning the handshake
   */
  int getRequiredPreSharedKeyCount() {
    return Math.toIntExact(Arrays.stream(getHandshakeMessagePatterns())
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .filter(token -> token == Token.PSK)
        .count());
  }

  /**
   * Checks whether the party with the given role in this handshake must supply a local static key pair prior to
   * beginning the handshake.
   *
   * @param role the role of the party in this handshake
   *
   * @return {@code true} if the given party must provide a local static key pair prior to beginning the handshake or
   * {@code false} otherwise
   */
  boolean requiresLocalStaticKeyPair(final NoiseHandshake.Role role) {
    // The given role needs a local static key pair if any pre-handshake message or handshake message involves that role
    // sending a static key to the other party
    return Stream.concat(Arrays.stream(getPreMessagePatterns()), Arrays.stream(getHandshakeMessagePatterns()))
        .filter(messagePattern -> messagePattern.sender() == role)
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == Token.S);
  }

  /**
   * Checks whether the party with the given role in this handshake must supply a remote ephemeral public key prior to
   * beginning the handshake.
   *
   * @param role the role of the party in this handshake
   *
   * @return {@code true} if the given party must provide a remote ephemeral public key prior to beginning the handshake
   * or {@code false} otherwise
   */
  boolean requiresRemoteEphemeralPublicKey(final NoiseHandshake.Role role) {
    // The given role needs a remote static key pair if the handshake pattern involves that role receiving an ephemeral
    // key from the other party in a pre-handshake message
    return Arrays.stream(getPreMessagePatterns())
        .filter(messagePattern -> messagePattern.sender() != role)
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == Token.E);
  }

  /**
   * Checks whether the party with the given role in this handshake must supply a remote static public key prior to
   * beginning the handshake.
   *
   * @param role the role of the party in this handshake
   *
   * @return {@code true} if the given party must provide a remote static public key prior to beginning the handshake or
   * {@code false} otherwise
   */
  boolean requiresRemoteStaticPublicKey(final NoiseHandshake.Role role) {
    // The given role needs a remote static key pair if the handshake pattern involves that role receiving a static key
    // from the other party in a pre-handshake message
    return Arrays.stream(getPreMessagePatterns())
        .filter(messagePattern -> messagePattern.sender() != role)
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == Token.S);
  }

  @Override
  public String toString() {
    final StringBuilder stringBuilder = new StringBuilder(getName() + ":\n");

    // We know we can't end on a pre-message pattern line, so we can unconditionally append newlines after each
    // pre-handshake message
    Arrays.stream(getPreMessagePatterns())
        .forEach(preMessagePattern -> {
          stringBuilder.append(preMessagePattern);
          stringBuilder.append('\n');
        });

    if (getPreMessagePatterns().length > 0) {
      stringBuilder.append("  ");
      stringBuilder.append(PRE_MESSAGE_SEPARATOR);
      stringBuilder.append('\n');
    }

    stringBuilder.append(Arrays.stream(getHandshakeMessagePatterns())
        .map(MessagePattern::toString)
        .collect(Collectors.joining("\n")));

    return stringBuilder.toString();
  }

  /**
   * Tests whether this handshake pattern is equal to another object. This handshake pattern is equal to the given
   * object if the given object is also a handshake pattern and has the same name and message patterns as this handshake
   * pattern.
   *
   * @param o the other object with which to check equality
   *
   * @return {@code true} if this handshake pattern is equal to the given object or {@code false} otherwise
   */
  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    } else if (o instanceof final HandshakePattern that) {
      return Objects.equals(name, that.name)
          && Arrays.equals(preMessagePatterns, that.preMessagePatterns)
          && Arrays.equals(handshakeMessagePatterns, that.handshakeMessagePatterns);
    } else {
      return false;
    }
  }

  /**
   * Returns a hash code value for this handshake pattern.
   *
   * @return a hash code value for this handshake pattern
   */
  @Override
  public int hashCode() {
    int result = Objects.hash(name);
    result = 31 * result + Arrays.hashCode(preMessagePatterns);
    result = 31 * result + Arrays.hashCode(handshakeMessagePatterns);
    return result;
  }
}
