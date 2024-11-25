package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.lark.DeviceException;

public class LedgerTransportException extends DeviceException {
    protected final Transport.Response response;

    public LedgerTransportException(Transport.Response response) {
        super(getMessage(response.sw(), "Invalid status: 0x" + String.format("%04X", response.sw())));
        this.response = response;
    }

    protected LedgerTransportException(Transport.Response response, String defaultMessage) {
        super(getMessage(response.sw(), defaultMessage));
        this.response = response;
    }

    public Transport.Response getResponse() {
        return response;
    }

    protected static String getMessage(int code, String defaultMessage) {
        return switch(code) {
            case 0x6982 -> "Command not valid for security reasons";
            case 0x6985 -> "Denied by user";
            case 0x6A80 -> "Incorrect data";
            case 0x6A82 -> "Request not currently supported";
            case 0x6A87 -> "Incorrect data length";
            case 0x6D00 -> "Unknown command with this INS";
            case 0x6E00 -> "Instruction class is different than CLA";
            case 0xB000 -> "Wrong response length (buffer too small or too big)";
            case 0xB007 -> "Bad device state";
            case 0xB008 -> "Signature fail";
            case 0xE000 -> "Interrupted execution";
            case 0x5515 -> "The Ledger device is locked";
            default -> defaultMessage;
        };
    }
}
