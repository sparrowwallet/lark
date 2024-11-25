package com.sparrowwallet.lark.bitbox02;

import com.sparrowwallet.drongo.Utils;

public class BitBoxProtocolV4 extends BitBoxProtocolV3 {
    public BitBoxProtocolV4(TransportLayer transportLayer) {
        super(transportLayer);
    }

    @Override
    public byte[] encodeNoiseRequest(byte[] encryptedMsg) {
        return Utils.concat(OP_NOISE_MSG, encryptedMsg);
    }
}
