package com.sparrowwallet.lark.ledger.command;

import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.VarInt;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.ledger.ByteStreamParser;
import com.sparrowwallet.lark.ledger.MerkleUtils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;

public class GetMerkleLeafIndexCommand implements ClientCommand {
    private final Map<Sha256Hash, MerkleUtils.MerkleTree> knownTrees;

    public GetMerkleLeafIndexCommand(Map<Sha256Hash, MerkleUtils.MerkleTree> knownTrees) {
        this.knownTrees = knownTrees;
    }

    @Override
    public byte[] execute(byte[] request) throws DeviceException {
        ByteStreamParser req = new ByteStreamParser(Arrays.copyOfRange(request, 1, request.length));

        try {
            Sha256Hash root = Sha256Hash.wrap(req.readBytes(32));
            Sha256Hash leafHash = Sha256Hash.wrap(req.readBytes(32));
            req.assertEmpty();

            if(!knownTrees.containsKey(root)) {
                throw new DeviceException("Unknown merkle root: " + root);
            }

            int leafIndex = knownTrees.get(root).leafIndex(leafHash.getBytes());
            int found = leafIndex < 0 ? 0 : 1;
            leafIndex = Math.max(leafIndex, 0);

            byte[] leafIndexOut = new VarInt(leafIndex).encode();
            ByteBuffer buf = ByteBuffer.allocate(1 + leafIndexOut.length);
            buf.put((byte)found);
            buf.put(leafIndexOut);
            return buf.array();
        } catch(IOException e) {
            throw new DeviceException("Device IO error", e);
        }
    }

    @Override
    public int code() {
        return ClientCommandCode.GET_MERKLE_LEAF_INDEX.getCode();
    }
}
