package com.sparrowwallet.lark.ledger.command;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.lark.DeviceException;

import java.nio.ByteBuffer;
import java.util.Deque;

public class GetMoreElementsCommand implements ClientCommand {
    private final Deque<byte[]> queue;

    public GetMoreElementsCommand(Deque<byte[]> queue) {
        this.queue = queue;
    }

    @Override
    public byte[] execute(byte[] request) throws DeviceException {
        if(request.length != 1) {
            throw new DeviceException("Wrong request length");
        }

        if(queue.isEmpty()) {
            throw new DeviceException("No elements to get");
        }

        int elementLen = queue.peekFirst().length;
        if(!queue.stream().allMatch(element -> element.length == elementLen)) {
            throw new DeviceException("The queue contains elements of different byte length, which is not expected");
        }

        // pop from the queue, keeping the total response length at most 255

        byte[] responseElements = new byte[0];

        int nAddedElements = 0;
        while(!queue.isEmpty() && (responseElements.length + elementLen <= 253)) {
            responseElements = Utils.concat(responseElements, queue.pop());
            nAddedElements++;
        }

        ByteBuffer buf = ByteBuffer.allocate(1 + 1 + responseElements.length);
        buf.put((byte)nAddedElements);
        buf.put((byte)elementLen);
        buf.put(responseElements);
        return buf.array();
    }

    @Override
    public int code() {
        return ClientCommandCode.GET_MORE_ELEMENTS.getCode();
    }
}
