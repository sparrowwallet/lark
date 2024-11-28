package com.sparrowwallet.lark.bitbox02.noise.crypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigestSpi;
import java.util.Arrays;

class Blake2bMessageDigestSpi extends MessageDigestSpi {

  private final int hashLength;

  private final byte[] keyBlock;
  private final int keyLength;

  private final long[] state = new long[8];
  private long bytesHashed;

  private final byte[] block = new byte[BLOCK_SIZE];
  private int blockOffset;

  private static final int BLOCK_SIZE = 128;

  private static final long[] IV = new long[]{
      0x6a09e667f3bcc908L,
      0xbb67ae8584caa73bL,
      0x3c6ef372fe94f82bL,
      0xa54ff53a5f1d36f1L,
      0x510e527fade682d1L,
      0x9b05688c2b3e6c1fL,
      0x1f83d9abfb41bd6bL,
      0x5be0cd19137e2179L
  };

  private static final byte[][] SIGMA = new byte[][] {
      new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
      new byte[] { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
      new byte[] { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
      new byte[] { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
      new byte[] { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
      new byte[] { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
      new byte[] { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
      new byte[] { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
      new byte[] { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
      new byte[] { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
      new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
      new byte[] { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
  };

  public Blake2bMessageDigestSpi(final int hashLength) {
    this(hashLength, null);
  }

  public Blake2bMessageDigestSpi(final int hashLength, final byte[] key) {
    if (hashLength < 1 || hashLength > 64) {
      throw new IllegalArgumentException("Hash length must be between 1 and 64 bytes");
    }

    if (key != null && key.length > 64) {
      throw new IllegalArgumentException("Keys may be at most 64 bytes");
    }

    this.hashLength = hashLength;

    if (key != null && key.length > 0) {
      this.keyBlock = new byte[BLOCK_SIZE];
      this.keyLength = key.length;

      System.arraycopy(key, 0, keyBlock, 0, keyLength);
    } else {
      this.keyBlock = new byte[0];
      this.keyLength = 0;
    }

    engineReset();
  }

  @Override
  protected int engineGetDigestLength() {
    return hashLength;
  }

  @Override
  protected void engineReset() {
    System.arraycopy(IV, 0, state, 0, IV.length);
    state[0] ^= 0x01010000 ^ ((long) keyLength << 8) ^ hashLength;

    System.arraycopy(keyBlock, 0, block, 0, keyLength);
    Arrays.fill(block, keyLength, BLOCK_SIZE, (byte) 0);
    blockOffset = 0;
    bytesHashed = 0;

    engineUpdate(keyBlock, 0, keyBlock.length);
  }

  @Override
  protected void engineUpdate(final byte input) {
    if (blockOffset == BLOCK_SIZE) {
      // We have a full block already. Process it to make room for the new byte
      compress(block, 0, false);
      blockOffset = 0;
    }

    block[blockOffset++] = input;
    bytesHashed += 1;
  }

  @Override
  protected void engineUpdate(final byte[] input, final int offset, final int len) {
    if (len == 0) {
      return;
    }

    int inputPosition = 0;

    if (blockOffset > 0) {
      // We have a partial block; complete it if we can
      final int copiedBytes = Math.min(BLOCK_SIZE - blockOffset, len);
      System.arraycopy(input, offset, block, blockOffset, copiedBytes);

      inputPosition += copiedBytes;
      blockOffset += copiedBytes;
      bytesHashed += copiedBytes;
    }

    // Do we have (a) a full block and (b) more bytes to process? If so, flush the block.
    if (blockOffset == BLOCK_SIZE && len - inputPosition > 0) {
      compress(block, 0, false);
      blockOffset = 0;
    }

    // At this point, we either have a partial block and no more bytes to process OR we have a full block and more bytes
    // to process. If we're in the latter case, process full blocks in place (as opposed to copying them), but save the
    // last block in case it turns out to be the last block (in which case it needs special handling).
    while (len - inputPosition > BLOCK_SIZE) {
      bytesHashed += BLOCK_SIZE;
      compress(input, offset + inputPosition, false);

      inputPosition += BLOCK_SIZE;
    }

    // Copy any remaining bytes into the partial block buffer
    System.arraycopy(input, offset + inputPosition, block, blockOffset, len - inputPosition);
    blockOffset += len - inputPosition;
    bytesHashed += len - inputPosition;
  }

  @Override
  protected byte[] engineDigest() {
    if (blockOffset < BLOCK_SIZE) {
      Arrays.fill(block, blockOffset, BLOCK_SIZE, (byte) 0x00);
    }

    compress(block, 0, true);

    final ByteBuffer hashBuffer = ByteBuffer.allocate(BLOCK_SIZE).order(ByteOrder.LITTLE_ENDIAN);

    for (final long i : state) {
      hashBuffer.putLong(i);
    }

    hashBuffer.flip();

    final byte[] hash = new byte[hashLength];
    hashBuffer.get(hash);

    try {
      return hash;
    } finally {
      engineReset();
    }
  }

  private static void mix(final long[] v, final int a, final int b, final int c, final int d, final long x, final long y) {
    v[a] = v[a] + v[b] + x;
    v[d] = Long.rotateRight(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];
    v[b] = Long.rotateRight(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = Long.rotateRight(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = Long.rotateRight(v[b] ^ v[c], 63);
  }

  private void compress(final byte[] bytes, final int offset, final boolean lastBlock) {
    final long[] messageBlock = new long[16];

    // Parse bytes as little-endian longs
    for (int i = 0; i < 16; i++) {
      messageBlock[i] = (long) bytes[offset + (i * 8)] & 0xff |
          (long) (bytes[offset + (i * 8) + 1] & 0xff) << 8 |
          (long) (bytes[offset + (i * 8) + 2] & 0xff) << 16 |
          (long) (bytes[offset + (i * 8) + 3] & 0xff) << 24 |
          (long) (bytes[offset + (i * 8) + 4] & 0xff) << 32 |
          (long) (bytes[offset + (i * 8) + 5] & 0xff) << 40 |
          (long) (bytes[offset + (i * 8) + 6] & 0xff) << 48 |
          (long) (bytes[offset + (i * 8) + 7] & 0xff) << 56;
    }

    final long[] v = new long[16];
    System.arraycopy(state, 0, v, 0, state.length);
    System.arraycopy(IV, 0, v, 8, IV.length);

    // Note: technically, this isn't right. BLAKE2b is supposed to support streams of up to 2^128 bytes, but this only
    // goes up to 2^64. If we're hashing 1GiB/sec, though, it's still going to take nearly 300 years of processing a
    // single stream before this becomes a problem. If anybody actually runs into this, please file a bug report so we
    // can coordinate delivery of your trophy.
    //
    // Also, this is (for now) intended for use with Noise, which limits message sizes to 64KiB.
    v[12] ^= bytesHashed;

    if (lastBlock) {
      v[14] = ~v[14];
    }

    for (final byte[] schedule : SIGMA) {
      mix(v, 0, 4,  8, 12, messageBlock[schedule[ 0]], messageBlock[schedule[ 1]]);
      mix(v, 1, 5,  9, 13, messageBlock[schedule[ 2]], messageBlock[schedule[ 3]]);
      mix(v, 2, 6, 10, 14, messageBlock[schedule[ 4]], messageBlock[schedule[ 5]]);
      mix(v, 3, 7, 11, 15, messageBlock[schedule[ 6]], messageBlock[schedule[ 7]]);

      mix(v, 0, 5, 10, 15, messageBlock[schedule[ 8]], messageBlock[schedule[ 9]]);
      mix(v, 1, 6, 11, 12, messageBlock[schedule[10]], messageBlock[schedule[11]]);
      mix(v, 2, 7,  8, 13, messageBlock[schedule[12]], messageBlock[schedule[13]]);
      mix(v, 3, 4,  9, 14, messageBlock[schedule[14]], messageBlock[schedule[15]]);
    }

    for (int i = 0; i < 8; i++) {
      state[i] ^= v[i] ^ v[i + 8];
    }
  }
}
