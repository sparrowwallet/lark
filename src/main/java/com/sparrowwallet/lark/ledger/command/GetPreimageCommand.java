package com.sparrowwallet.lark.ledger.command;

import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.VarInt;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.ledger.ByteStreamParser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

public class GetPreimageCommand implements ClientCommand {
    private final Map<Sha256Hash, byte[]> knownPreimages;
    private final Deque<byte[]> queue;

    public GetPreimageCommand(Map<Sha256Hash, byte[]> knownPreimages, Deque<byte[]> queue) {
        this.knownPreimages = knownPreimages;
        this.queue = queue;
    }

    @Override
    public byte[] execute(byte[] request) throws DeviceException {
        ByteStreamParser req = new ByteStreamParser(Arrays.copyOfRange(request, 1, request.length));

        try {
            if(!Arrays.equals(req.readBytes(1), new byte[] { 0 })) {
                throw new DeviceException("Unsupported request: the first byte should be 0");
            }

            Sha256Hash reqHash = Sha256Hash.wrap(req.readBytes(32));
            req.assertEmpty();

            if(knownPreimages.containsKey(reqHash)) {
                byte[] knownPreimage = knownPreimages.get(reqHash);
                byte[] preimageLenOut = new VarInt(knownPreimage.length).encode();

                // We can send at most 255 - len(preimage_len_out) - 1 bytes in a single message;
                // the rest will be stored for GET_MORE_ELEMENTS

                int maxPayloadSize = 255 - preimageLenOut.length - 1;
                int payloadSize = Math.min(maxPayloadSize, knownPreimage.length);

                if(payloadSize < knownPreimage.length) {
                    // split into list of length-1 bytes elements
                    List<byte[]> extraElements = new ArrayList<>();
                    for(int i = payloadSize; i < knownPreimage.length; i++) {
                        extraElements.add(new byte[]{ knownPreimage[i] });
                    }
                    // add to the queue any remaining extra bytes
                    queue.addAll(extraElements);
                }

                ByteBuffer buf = ByteBuffer.allocate(preimageLenOut.length + 1 + payloadSize);
                buf.put(preimageLenOut);
                buf.put((byte)payloadSize);
                buf.put(knownPreimage, 0, payloadSize);
                return buf.array();
            }

            throw new DeviceException("Requested unknown preimage for: " + reqHash);
        } catch(IOException e) {
            throw new DeviceException("Device IO error", e);
        }
    }

    @Override
    public int code() {
        return ClientCommandCode.GET_PREIMAGE.getCode();
    }
}
