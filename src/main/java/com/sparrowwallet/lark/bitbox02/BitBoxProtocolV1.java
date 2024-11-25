package com.sparrowwallet.lark.bitbox02;

import com.sparrowwallet.lark.DeviceException;

public class BitBoxProtocolV1 extends BitBoxProtocol {
    public BitBoxProtocolV1(TransportLayer transportLayer) {
        super(transportLayer);
    }

    @Override
    public void unlockQuery() throws DeviceException {
        throw new UnsupportedOperationException("unlock_query is not supported in BitBox protocol V1");
    }

    @Override
    public byte[] encodeNoiseRequest(byte[] encryptedMsg) {
        return encryptedMsg;
    }

    @Override
    public Response decodeNoiseResponse(byte[] encryptedMsg) {
        if(encryptedMsg.length == 0) {
            return new Response(RESPONSE_FAILURE, new byte[0]);
        }
        return new Response(RESPONSE_SUCCESS, encryptedMsg);
    }

    @Override
    public Response handshakeQuery(byte[] req) throws DeviceException {
        byte[] result = rawQuery(req);
        return new Response(RESPONSE_SUCCESS, result);
    }

    @Override
    public void cancelOutstandingRequest() {
        throw new RuntimeException("cancel_outstanding_request should never be called here");
    }
}
