package com.sparrowwallet.lark.ledger.command;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.ledger.MerkleUtils;

import java.util.*;

public class ClientCommandInterpreter {
    private final Map<Sha256Hash, byte[]> knownPreimages = new HashMap<>();
    private final Map<Sha256Hash, MerkleUtils.MerkleTree> knownTrees = new HashMap<>();
    List<byte[]> yielded = new ArrayList<>();
    Deque<byte[]> queue = new ArrayDeque<>();

    List<ClientCommand> commands = List.of(new YieldCommand(yielded), new GetPreimageCommand(knownPreimages, queue), new GetMerkleLeafIndexCommand(knownTrees),
            new GetMerkleLeafProofCommand(knownTrees, queue), new GetMoreElementsCommand(queue));

    /**
     * Interprets the client command requested by the hardware wallet, returning the appropriate
     * response and updating the client interpreter's internal state if appropriate.
     *
     * @param hwResponse The data content of the SW_INTERRUPTED_EXECUTION sent by the hardware wallet
     * @return The result of the execution of the appropriate client side command, containing the response to be sent via INS_CONTINUE
     * @throws DeviceException on an error
     */
    public byte[] execute(byte[] hwResponse) throws DeviceException {
        if(hwResponse.length == 0) {
            throw new DeviceException("Unexpected empty SW_INTERRUPTED_EXECUTION response from hardware wallet");
        }

        byte commandCode = hwResponse[0];
        for(ClientCommand command : commands) {
            if(command.code() == commandCode) {
                return command.execute(hwResponse);
            }
        }

        throw new DeviceException("Unknown command code: " + commandCode);
    }

    /**
     * Adds a preimage to the list of known preimages.
     *
     * The client must respond with `element` when a GET_PREIMAGE command is sent with `sha256(element)` in its request.
     *
     * @param element An array of bytes whose preimage must be known to the client during an APDU execution
     */
    public void addKnownPreimage(byte[] element) {
        knownPreimages.put(Sha256Hash.of(element), element);
    }

    /**
     * Adds a known Merkleized list.
     * Builds the Merkle tree of `elements`, and adds it to the Merkle trees known to the client
     * (mapped by Merkle root `mt_root`).
     *
     * moreover, adds all the leafs (after adding the zero byte prefix) to the list of known preimages.
     * If `el` is one of `elements`, the client must respond with b'\0' + `el` when a GET_PREIMAGE
     * client command is sent with `sha256(b'\0' + el)`.
     *
     * Moreover, the commands GET_MERKLE_LEAF_INDEX and GET_MERKLE_LEAF_PROOF must correctly answer
     * queries relative to the Merkle whose root is `mt_root`.
     *
     * @param elements A List of `byte[]` corresponding to the leafs of the Merkle tree
     */
    public void addKnownList(List<byte[]> elements) {
        for(byte[] element : elements) {
            addKnownPreimage(Utils.concat(new byte[] { 0 }, element));
        }

        MerkleUtils.MerkleTree tree = MerkleUtils.buildTree(elements.stream().map(e -> MerkleUtils.hashElement(e).getBytes()).toList());
        knownTrees.put(tree.getRootHash(), tree);
    }

    /**
     * Adds the Merkle trees of keys, and the Merkle tree of values (ordered by key)
     * of a mapping of bytes to bytes.
     *
     * Adds the Merkle tree of the list of keys, and the Merkle tree of the list of corresponding
     * values, with the same semantics as the `add_known_list` applied separately to the two lists.
     *
     * @param mapping the mapping to add
     */
    public void addKnownMapping(Map<byte[], byte[]> mapping) {
        List<Map.Entry<byte[], byte[]>> sorted = mapping.entrySet().stream().sorted(Map.Entry.comparingByKey(Arrays::compareUnsigned)).toList();
        addKnownList(sorted.stream().map(Map.Entry::getKey).toList());
        addKnownList(sorted.stream().map(Map.Entry::getValue).toList());
    }

    public List<byte[]> getYielded() {
        return yielded;
    }
}
