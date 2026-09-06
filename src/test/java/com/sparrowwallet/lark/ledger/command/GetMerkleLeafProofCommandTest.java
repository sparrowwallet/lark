package com.sparrowwallet.lark.ledger.command;

import com.sparrowwallet.drongo.protocol.VarInt;
import com.sparrowwallet.lark.DeviceException;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class GetMerkleLeafProofCommandTest {
    @Test
    public void testProofResponsesAtTreeBoundaries() throws Exception {
        for(int size : new int[] {1, 64, 65, 111, 128, 129, 512}) {
            List<byte[]> elements = elements(size);
            List<byte[]> leaves = hashLeaves(elements);
            byte[] root = merkleRoot(leaves);
            ClientCommandInterpreter client = new ClientCommandInterpreter();
            client.addKnownList(elements);

            for(int index = 0; index < size; index++) {
                checkProof(client, leaves, root, index);
            }
        }
    }

    @Test
    public void testProofSpanningMultipleContinuations() throws Exception {
        // A 14-hash proof needs six hashes initially, then seven and one.
        List<byte[]> elements = elements(8193);
        List<byte[]> leaves = hashLeaves(elements);
        byte[] root = merkleRoot(leaves);
        ClientCommandInterpreter client = new ClientCommandInterpreter();
        client.addKnownList(elements);

        checkProof(client, leaves, root, 0);
        checkProof(client, leaves, root, 8192);
    }

    private static void checkProof(ClientCommandInterpreter client, List<byte[]> leaves, byte[] root, int index) throws Exception {
        String context = "size=" + leaves.size() + ", index=" + index;
        List<ProofStep> expected = proof(leaves, index);
        ByteArrayOutputStream request = new ByteArrayOutputStream();
        request.write(ClientCommandCode.GET_MERKLE_LEAF_PROOF.getCode());
        request.write(root);
        request.write(new VarInt(leaves.size()).encode());
        request.write(new VarInt(index).encode());

        byte[] first = client.execute(request.toByteArray());
        int initial = Math.min(expected.size(), 6);
        assertEquals(34 + initial * 32, first.length, context);
        assertArrayEquals(leaves.get(index), Arrays.copyOf(first, 32), context);
        assertEquals(expected.size(), Byte.toUnsignedInt(first[32]), context);
        assertEquals(initial, Byte.toUnsignedInt(first[33]), context);

        List<byte[]> received = new ArrayList<>();
        for(int i = 0; i < initial; i++) {
            received.add(Arrays.copyOfRange(first, 34 + i * 32, 34 + (i + 1) * 32));
        }

        byte[] moreRequest = {(byte)ClientCommandCode.GET_MORE_ELEMENTS.getCode()};
        while(received.size() < expected.size()) {
            byte[] more = client.execute(moreRequest);
            int count = Math.min(expected.size() - received.size(), 7);
            assertEquals(2 + count * 32, more.length, context);
            assertEquals(count, Byte.toUnsignedInt(more[0]), context);
            assertEquals(32, Byte.toUnsignedInt(more[1]), context);
            for(int i = 0; i < count; i++) {
                received.add(Arrays.copyOfRange(more, 2 + i * 32, 2 + (i + 1) * 32));
            }
        }

        byte[] reconstructed = leaves.get(index);
        for(int i = 0; i < expected.size(); i++) {
            ProofStep step = expected.get(i);
            byte[] sibling = received.get(i);
            assertArrayEquals(step.sibling(), sibling, context + ", proof element=" + i);
            reconstructed = step.rightChild() ? hashNode(sibling, reconstructed) : hashNode(reconstructed, sibling);
        }
        assertArrayEquals(root, reconstructed, context);
        DeviceException empty = assertThrows(DeviceException.class, () -> client.execute(moreRequest), context);
        assertEquals("No elements to get", empty.getMessage(), context);
    }

    private static List<byte[]> elements(int size) {
        List<byte[]> elements = new ArrayList<>();
        for(int i = 0; i < size; i++) {
            elements.add(("leaf:" + i).getBytes(StandardCharsets.US_ASCII));
        }
        return elements;
    }

    // Build the expected tree and proof independently of MerkleUtils.
    private static List<byte[]> hashLeaves(List<byte[]> elements) throws Exception {
        List<byte[]> leaves = new ArrayList<>();
        for(byte[] element : elements) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update((byte)0);
            leaves.add(digest.digest(element));
        }
        return leaves;
    }

    private static byte[] merkleRoot(List<byte[]> leaves) throws Exception {
        if(leaves.size() == 1) {
            return leaves.getFirst();
        }
        int split = Integer.highestOneBit(leaves.size() - 1);
        return hashNode(merkleRoot(leaves.subList(0, split)), merkleRoot(leaves.subList(split, leaves.size())));
    }

    private static List<ProofStep> proof(List<byte[]> leaves, int index) throws Exception {
        List<ProofStep> proof = new ArrayList<>();
        while(leaves.size() > 1) {
            int split = Integer.highestOneBit(leaves.size() - 1);
            if(index < split) {
                proof.addFirst(new ProofStep(merkleRoot(leaves.subList(split, leaves.size())), false));
                leaves = leaves.subList(0, split);
            } else {
                proof.addFirst(new ProofStep(merkleRoot(leaves.subList(0, split)), true));
                leaves = leaves.subList(split, leaves.size());
                index -= split;
            }
        }
        return proof;
    }

    private static byte[] hashNode(byte[] left, byte[] right) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update((byte)1);
        digest.update(left);
        return digest.digest(right);
    }

    private record ProofStep(byte[] sibling, boolean rightChild) {}
}
