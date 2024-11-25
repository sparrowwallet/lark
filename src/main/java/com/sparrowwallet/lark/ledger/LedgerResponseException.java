package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.lark.ledger.command.BitcoinInsType;
import com.sparrowwallet.lark.ledger.command.DefaultInsType;
import com.sparrowwallet.lark.ledger.command.FrameworkInsType;

public class LedgerResponseException extends LedgerTransportException {
    private final String command;

    public LedgerResponseException(Transport.Response response, DefaultInsType command) {
        this(response, command.name());
    }

    public LedgerResponseException(Transport.Response response, BitcoinInsType command) {
        this(response, command.name());
    }

    public LedgerResponseException(Transport.Response response, FrameworkInsType command) {
        this(response, command.name());
    }

    protected LedgerResponseException(Transport.Response response, String command) {
        super(response, "Unexpected response to " + command + ": 0x" + String.format("%04X", response.sw()));
        this.command = command;
    }

    public int getCode() {
        return response.sw();
    }

    public String getCommand() {
        return command;
    }
}
