package com.sparrowwallet.lark.ledger.command;

import java.util.Arrays;
import java.util.List;

public class YieldCommand implements ClientCommand {
    private final List<byte[]> results;

    public YieldCommand(List<byte[]> results) {
        this.results = results;
    }

    @Override
    public byte[] execute(byte[] request) {
        results.add(Arrays.copyOfRange(request, 1, request.length));
        return new byte[0];
    }

    @Override
    public int code() {
        return ClientCommandCode.YIELD.getCode();
    }
}
