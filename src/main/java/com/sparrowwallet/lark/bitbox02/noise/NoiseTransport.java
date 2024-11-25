package com.sparrowwallet.lark.bitbox02.noise;

/**
 * <p>A Noise transport is an interactive reader and writer of Noise transport messages. In the terminology of the Noise
 * Protocol Framework specification, a {@code NoiseTransport} instance encapsulates the two "cipher states" produced by
 * "splitting" a {@link NoiseHandshake}.</p>
 *
 * <p>Noise transport instances are stateful and are <em>not</em> thread-safe.</p>
 *
 * @see NoiseHandshake#toTransport()
 */
public interface NoiseTransport extends NoiseTransportReader, NoiseTransportWriter {
}
