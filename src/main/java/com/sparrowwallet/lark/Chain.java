package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.Network;

public enum Chain {
    main(Network.MAINNET), test(Network.TESTNET), regtest(Network.REGTEST), signet(Network.SIGNET);

    private final Network network;

    Chain(Network network) {
        this.network = network;
    }

    public Network getNetwork() {
        return network;
    }
}
