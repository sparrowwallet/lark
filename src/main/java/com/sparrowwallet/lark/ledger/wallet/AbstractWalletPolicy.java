package com.sparrowwallet.lark.ledger.wallet;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class AbstractWalletPolicy {
    protected final String name;
    protected final WalletType version;

    public AbstractWalletPolicy(String name, WalletType version) {
        this.name = name;
        this.version = version;

        if(version != WalletType.WALLET_POLICY_V1 && version != WalletType.WALLET_POLICY_V2) {
            throw new IllegalArgumentException("Unsupported wallet version: " + version);
        }
    }

    public String getName() {
        return name;
    }

    public WalletType getVersion() {
        return version;
    }

    public byte[] serialize() {
        byte[] nameBytes = serialize(name);
        ByteBuffer buf = ByteBuffer.allocate(1 + nameBytes.length);
        buf.put((byte)version.getVersion());
        buf.put(nameBytes);
        return buf.array();
    }

    public Sha256Hash id() {
        return Sha256Hash.of(serialize());
    }

    protected byte[] serialize(String str) {
        ByteBuffer buf = ByteBuffer.allocate(1 + str.length());
        buf.put((byte)name.length());
        buf.put(str.getBytes(StandardCharsets.ISO_8859_1));
        return buf.array();
    }
}
