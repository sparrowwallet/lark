package com.sparrowwallet.lark.bitbox02;

import com.sparrowwallet.lark.DeviceException;

public class BitBoxProtocolV2 extends BitBoxProtocolV1 {
    public BitBoxProtocolV2(TransportLayer transportLayer) {
        super(transportLayer);
    }

    @Override
    public void unlockQuery() throws DeviceException {
        byte[] unlockData = rawQuery(OP_UNLOCK);
        if(unlockData.length != 0) {
            throw new DeviceException("OP_UNLOCK (V2) replied with wrong length");
        }
    }
}
