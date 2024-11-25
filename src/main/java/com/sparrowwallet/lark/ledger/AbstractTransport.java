package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.lark.DeviceException;

public abstract class AbstractTransport implements Transport {
    @Override
    public Response apduExchange(APDUCommand apduCommand) throws DeviceException {
        Response response = exchange(apduCommand.getBytes());
        if(response.sw() != 0x9000) {
            throw new LedgerTransportException(response);
        }
        return response;
    }
}
