package com.sparrowwallet.lark.ledger.wallet;

import com.sparrowwallet.drongo.protocol.ScriptType;

import java.util.List;
import java.util.StringJoiner;

public class MultisigWalletPolicy extends WalletPolicy {
    private final int threshold;

    public MultisigWalletPolicy(String name, ScriptType scriptType, int threshold, List<String> keysInfo) {
        this(name, scriptType, threshold, keysInfo, true, WalletType.WALLET_POLICY_V2);
    }

    public MultisigWalletPolicy(String name, ScriptType scriptType, int threshold, List<String> keysInfo, boolean sorted, WalletType version) {
        super(sanitizeName(name), getDescriptorTemplate(scriptType, threshold, keysInfo, sorted, version), keysInfo, version);
        this.threshold = threshold;
    }

    private static String getDescriptorTemplate(ScriptType scriptType, int threshold, List<String> keysInfo, boolean sorted, WalletType version) {
        if(threshold < 1 || threshold > keysInfo.size() || keysInfo.size() > 16) {
            throw new IllegalArgumentException("Invalid threshold or number of keys");
        }

        StringBuilder builder = new StringBuilder();
        builder.append(scriptType.getDescriptor());
        builder.append(ScriptType.MULTISIG.getDescriptor());
        StringJoiner joiner = new StringJoiner(",");
        joiner.add(Integer.toString(threshold));
        for(int i = 0; i < keysInfo.size(); i++) {
            joiner.add("@" + i + (version == WalletType.WALLET_POLICY_V2 ? "/**" : ""));
        }
        builder.append(joiner);
        builder.append(ScriptType.MULTISIG.getCloseDescriptor());
        builder.append(scriptType.getCloseDescriptor());

        return builder.toString();
    }

    public int getThreshold() {
        return threshold;
    }

    private static String sanitizeName(String name) {
        String cleanName = name.trim().replaceAll("[^\\x20-\\x7E]", "_");
        if(cleanName.isEmpty()) {
            cleanName = "Wallet";
        } else if(cleanName.length() > MAX_NAME_LENGTH) {
            cleanName = cleanName.substring(0, MAX_NAME_LENGTH);
        }

        return cleanName;
    }
}
