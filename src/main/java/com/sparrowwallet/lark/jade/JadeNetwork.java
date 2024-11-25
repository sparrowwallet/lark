package com.sparrowwallet.lark.jade;

import com.sparrowwallet.drongo.Network;

public enum JadeNetwork {
    MAIN, TEST, ALL;

    public Network getNetwork() {
        return this == TEST ? Network.TESTNET : Network.MAINNET;
    }

    public static JadeNetwork fromNetwork(Network network) {
        return network == Network.TESTNET ? TEST : MAIN;
    }
}
