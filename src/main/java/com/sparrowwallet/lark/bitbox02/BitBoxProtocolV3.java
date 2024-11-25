package com.sparrowwallet.lark.bitbox02;

import com.sparrowwallet.lark.DeviceException;

import java.util.Arrays;

public class BitBoxProtocolV3 extends BitBoxProtocolV2 {
    public BitBoxProtocolV3(TransportLayer transportLayer) {
        super(transportLayer);
    }

    @Override
    public void unlockQuery() throws DeviceException {
        Response response = query(OP_UNLOCK, new byte[0]);
        if(response.data.length != 0) {
            throw new DeviceException("OP_UNLOCK (V3) replied with wrong length");
        }
        if(Arrays.equals(response.status,RESPONSE_FAILURE)) {
            throw new DeviceException("Unlock process aborted");
        }
    }
}
