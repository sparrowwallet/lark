package com.sparrowwallet.lark.ledger.command;

import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.ledger.ByteStreamParser;
import com.sparrowwallet.lark.ledger.MerkleUtils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import java.util.Map;

public class GetMerkleLeafProofCommand implements ClientCommand {
    private final Map<Sha256Hash, MerkleUtils.MerkleTree> knownTrees;
    private final Deque<byte[]> queue;

    public GetMerkleLeafProofCommand(Map<Sha256Hash, MerkleUtils.MerkleTree> knownTrees, Deque<byte[]> queue) {
        this.knownTrees = knownTrees;
        this.queue = queue;
    }

    @Override
    public byte[] execute(byte[] request) throws DeviceException {
        ByteStreamParser req = new ByteStreamParser(Arrays.copyOfRange(request, 1, request.length));

        try {
            Sha256Hash root = Sha256Hash.wrap(req.readBytes(32));
            long treeSize = req.readVarint();
            long leafIndex = req.readVarint();
            req.assertEmpty();

            if(!knownTrees.containsKey(root)) {
                throw new DeviceException("Unknown merkle root: " + root);
            }

            MerkleUtils.MerkleTree mt = knownTrees.get(root);

            if(leafIndex > treeSize || mt.size() != treeSize) {
                throw new DeviceException("Invalid index or tree size");
            }

            if(!queue.isEmpty()) {
                throw new DeviceException("This command should not execute when the queue is not empty");
            }

            List<byte[]> proof = mt.proveLeaf((int)leafIndex);

            // Compute how many elements we can fit in 255 - 32 - 1 - 1 = 221 bytes
            int nResponseElements = Math.min((255 - 32 - 1 - 1) / 32, proof.size());
            int nLeftoverElements = proof.size() - nResponseElements;

            if(nLeftoverElements > 0) {
                queue.addAll(proof.subList(0, proof.size() - nLeftoverElements));
            }

            ByteBuffer buf = ByteBuffer.allocate(32 + 1 + 1 + (nResponseElements * 32));
            buf.put(mt.get((int)leafIndex));
            buf.put((byte)proof.size());
            buf.put((byte)nResponseElements);
            for(int i = 0; i < nResponseElements; i++) {
                buf.put(proof.get(i));
            }
            return buf.array();
        } catch(IOException e) {
            throw new DeviceException("Device IO error", e);
        }
    }

    @Override
    public int code() {
        return ClientCommandCode.GET_MERKLE_LEAF_PROOF.getCode();
    }
}
