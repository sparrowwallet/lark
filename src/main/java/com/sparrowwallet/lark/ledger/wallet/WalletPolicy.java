package com.sparrowwallet.lark.ledger.wallet;

import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.VarInt;
import com.sparrowwallet.lark.ledger.MerkleUtils;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Represents a wallet stored with a wallet policy.
 *     For version V2, the wallet is serialized as follows:
 *        - 1 byte   : wallet version
 *        - 1 byte   : length of the wallet name (max 64)
 *        - (var)    : wallet name (ASCII string)
 *        - (varint) : length of the descriptor template
 *        - 32-bytes : sha256 hash of the descriptor template
 *        - (varint) : number of keys (not larger than 252)
 *        - 32-bytes : root of the Merkle tree of all the keys information.
 *
 *     The specific format of the keys is deferred to subclasses.
 */
public class WalletPolicy extends AbstractWalletPolicy {
    private final String descriptorTemplate;
    private final List<String> keysInfo;

    public WalletPolicy(String name, String descriptorTemplate, List<String> keysInfo) {
        this(name, descriptorTemplate, keysInfo, WalletType.WALLET_POLICY_V2);
    }

    public WalletPolicy(String name, String descriptorTemplate, List<String> keysInfo, WalletType version) {
        super(name, version);
        this.descriptorTemplate = descriptorTemplate;
        this.keysInfo = keysInfo;
    }

    public int getNumberOfKeys() {
        return keysInfo.size();
    }

    public String getDescriptorTemplate() {
        return descriptorTemplate;
    }

    public List<String> getKeysInfo() {
        return keysInfo;
    }

    @Override
    public byte[] serialize() {
        List<Sha256Hash> keysInfoHashes = keysInfo.stream().map(keyInfo -> MerkleUtils.hashElement(keyInfo.getBytes(StandardCharsets.ISO_8859_1))).toList();
        Sha256Hash descriptorTemplateHash = Sha256Hash.of(descriptorTemplate.getBytes(StandardCharsets.ISO_8859_1));

        byte[] nameAndVer = super.serialize();
        VarInt templateLength = new VarInt(descriptorTemplate.length());
        VarInt keysInfoLength = new VarInt(keysInfo.size());
        Sha256Hash root = MerkleUtils.getMerkleRoot(keysInfoHashes.stream().map(Sha256Hash::getBytes).toList());

        ByteBuffer buf;
        if(version == WalletType.WALLET_POLICY_V1) {
            buf = ByteBuffer.allocate(nameAndVer.length + templateLength.getOriginalSizeInBytes() + descriptorTemplate.length() + keysInfoLength.getOriginalSizeInBytes() + 32);
            buf.put(nameAndVer);
            buf.put(templateLength.encode());
            buf.put(descriptorTemplate.getBytes(StandardCharsets.ISO_8859_1));
            buf.put(keysInfoLength.encode());
            buf.put(root.getBytes());
            return buf.array();
        } else {
            buf = ByteBuffer.allocate(nameAndVer.length + templateLength.getOriginalSizeInBytes() + 32 + keysInfoLength.getOriginalSizeInBytes() + 32);
            buf.put(nameAndVer);
            buf.put(templateLength.encode());
            buf.put(descriptorTemplateHash.getBytes());
            buf.put(keysInfoLength.encode());
            buf.put(root.getBytes());
        }

        return buf.array();
    }

    public String getDescriptor(boolean change) {
        String desc = descriptorTemplate;
        for(int i = keysInfo.size() - 1; i >= 0; i--) {
            String key = keysInfo.get(i);
            desc = desc.replace("@" + i, key);
        }

        // in V1, /** is part of the key; in V2, it's part of the policy map. This handles either
        desc = desc.replace("/**", change ? "/1/*" : "/0/*");

        if(version == WalletType.WALLET_POLICY_V2) {
            // V2, the /<M;N> syntax is supported. Replace with M if not change, or with N if change
            String regex = "/<(\\d+);(\\d+)>";
            desc = desc.replaceAll(regex, change ? "/$2" : "/$1");
        }

        return desc;
    }
}
