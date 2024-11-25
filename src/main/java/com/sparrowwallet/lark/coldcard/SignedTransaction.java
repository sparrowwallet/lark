package com.sparrowwallet.lark.coldcard;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

public record SignedTransaction(long length, Sha256Hash sha256) {}
