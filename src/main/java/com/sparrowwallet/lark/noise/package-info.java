/**
 * <p>Provides classes and interfaces for performing handshakes and exchanging messages via a Noise protocol. This
 * package covers Noise handshakes and steady-state message transport.</p>
 *
 * <p>A Noise protocol begins with a handshake (see {@link com.sparrowwallet.lark.noise.NoiseHandshake}). During a handshake,
 * two parties exchange messages containing key material and optional, possibly-encrypted payloads as prescribed by a
 * chosen handshake pattern (see {@link com.sparrowwallet.lark.noise.HandshakePattern}). Once the handshake is complete, parties
 * exchange an effectively unbounded sequence of encrypted messages via a
 * {@link com.sparrowwallet.lark.noise.NoiseTransport}.</p>
 *
 * <h2>Example</h2>
 *
 * <p>The following example illustrates constructing Noise handshakes and exchanging messages via a steady-state Noise
 * transport. To begin, we choose a Noise protocol (in this case, {@code Noise_NN_25519_ChaChaPoly_SHA256}, which
 * specifies an NN handshake pattern, an X25519 key agreement algorithm, a ChaCha20-Poly1305 cipher, and a
 * SHA-256 hash). Then, we construct a pair of handshake objects. In most practical scenarios, the two "ends" of a
 * handshake are likely to be controlled by different processes (e.g. a client and server), but for this example, we
 * control both.</p>
 *
 * <p>Note that in this case, we construct the handshake objects by providing a full Noise protocol name to a
 * {@link com.sparrowwallet.lark.noise.NamedProtocolHandshakeBuilder}. For more complex handshake patterns, callers would be
 * responsible for providing any keys required for the handshake. Callers may wish to use
 * {@link com.sparrowwallet.lark.noise.NoiseHandshakeBuilder} for more complex handshake patterns, since its static initializer
 * methods provide compile-time assurances that the correct key material is provided for the chosen handshake pattern
 * and role.</p>
 *
 * <p>The NN handshake pattern is defined as:</p>
 *
 * <pre>NN:
 *   -&gt; e
 *   &lt;- e, ee</pre>
 *
 * <p>To carry out the handshake, we pass messages between the initiator and responder handshakes for each message
 * pattern in the handshake pattern. In the case of an NN handshake pattern, the initiator sends its ephemeral key to
 * the responder. The responder receives and processes the ephemeral key message, then sends its own ephemeral key to
 * the initiator and performs a DH key agreement operation between the two ephemeral keys. The initiator receives the
 * responder's ephemeral key and performs the same key agreement operation.</p>
 *
 * <p>With the handshake finished, the handshake objects can be "split" (in the terminology of the Noise protocol) into
 * steady-state transport channels, and then messages can be passed between the initiator and responder at will.</p>
 *
 * @see <a href="https://noiseprotocol.org/noise.html">The Noise Protocol Framework</a>
 */
package com.sparrowwallet.lark.noise;