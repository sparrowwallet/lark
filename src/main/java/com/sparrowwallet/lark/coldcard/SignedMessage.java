package com.sparrowwallet.lark.coldcard;

public record SignedMessage(String address, byte[] signature) {}
