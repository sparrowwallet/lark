package com.sparrowwallet.lark.bitbox02;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.lark.DeviceException;

import java.util.Arrays;

public class BitBoxProtocolV7 extends BitBoxProtocolV4 {
    private boolean cancelRequested;

    public BitBoxProtocolV7(TransportLayer transportLayer) {
        super(transportLayer);
    }

    @Override
    public Response handshakeQuery(byte[] req) throws DeviceException {
        return query(OP_HER_COMEZ_TEH_HANDSHAEK, req);
    }

    @Override
    public Response decodeNoiseResponse(byte[] encryptedMsg) {
        return new Response(Arrays.copyOfRange(encryptedMsg, 0, 1), Arrays.copyOfRange(encryptedMsg, 1, encryptedMsg.length));
    }

    @Override
    public byte[] rawQuery(byte[] msg) throws DeviceException {
        long cid = transportLayer.generateCid();
        byte[] status;
        byte[] payload;

        while(true) {
            byte[] response = transportLayer.query(Utils.concat(HwwRequestCode.REQ_NEW.getCode(), msg), HWW_CMD, cid);
            if(response.length == 0) {
                throw new DeviceException("Unexpected response of length 0 from HWW stack");
            }
            status = Arrays.copyOfRange(response, 0, 1);
            payload = Arrays.copyOfRange(response, 1, response.length);
            if(Arrays.equals(status, HwwResponseCode.RSP_BUSY.getCode())) {
                if(payload.length != 0) {
                    throw new DeviceException("Unexpected payload of length " + payload.length + " with RSP_BUSY response");
                }

                try {
                    Thread.sleep(1000);
                } catch(InterruptedException e) {
                    //ignore
                }
            } else {
                break;
            }
        }

        if(Arrays.equals(status, HwwResponseCode.RSP_NACK.getCode())) {
            throw new DeviceException("Unexpected NACK response from HWW stack");
        }

        //The message has been sent. If we have a retry, poll the device until we're ready.
        this.cancelRequested = false;
        while(Arrays.equals(status, HwwResponseCode.RSP_NOT_READY.getCode())) {
            if(payload.length != 0) {
                throw new DeviceException("Unexpected payload of length " + payload.length + " with RSP_NOT_READY response");
            }

            try {
                Thread.sleep(200);
            } catch(InterruptedException e) {
                //ignore
            }

            byte[] toSend = cancelRequested ? HwwRequestCode.REQ_CANCEL.getCode() : HwwRequestCode.REQ_RETRY.getCode();
            byte[] response = transportLayer.query(toSend, HWW_CMD, cid);
            if(response.length == 0) {
                throw new DeviceException("Unexpected response of length 0 from HWW stack");
            }
            status = Arrays.copyOfRange(response, 0, 1);
            payload = Arrays.copyOfRange(response, 1, response.length);
            if(!(Arrays.equals(status, HwwResponseCode.RSP_NOT_READY.getCode()) || Arrays.equals(status, HwwResponseCode.RSP_ACK.getCode()))) {
                throw new DeviceException("Unexpected response from HWW stack during retry " + Utils.bytesToHex(status));
            }
        }

        return payload;
    }

    @Override
    public void cancelOutstandingRequest() {
        cancelRequested = true;
    }
}
