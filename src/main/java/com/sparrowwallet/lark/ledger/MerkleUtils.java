package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.VarInt;
import com.sparrowwallet.drongo.psbt.PSBTEntry;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class MerkleUtils {
    public static Sha256Hash hashElement(byte[] preimage) {
        return Sha256Hash.of(Utils.concat(new byte[]{0x00}, preimage));
    }

    public static byte[] getMerkleizedMapCommitment(List<PSBTEntry> entry) {
        return getMerkleizedMapCommitment(entry.stream().collect(Collectors.toMap(PSBTEntry::getKey, PSBTEntry::getData)));
    }

    /**
     * Returns a serialized Merkleized map commitment, encoded as the concatenation of:
     * - the number of key/value pairs, as a Bitcoin-style varint;
     * - the root of the Merkle tree of the keys
     * - the root of the Merkle tree of the values.
     */
    public static byte[] getMerkleizedMapCommitment(Map<byte[], byte[]> mapping) {
        List<Map.Entry<byte[], byte[]>> sorted = mapping.entrySet().stream().sorted(Map.Entry.comparingByKey(Arrays::compareUnsigned)).toList();

        VarInt mappingLen = new VarInt(mapping.size());
        MerkleTree keysTree = buildTree(sorted.stream().map(Map.Entry::getKey).map(MerkleUtils::hashElement).map(Sha256Hash::getBytes).collect(Collectors.toList()));
        MerkleTree valuesTree = buildTree(sorted.stream().map(Map.Entry::getValue).map(MerkleUtils::hashElement).map(Sha256Hash::getBytes).collect(Collectors.toList()));

        ByteBuffer buf = ByteBuffer.allocate(mappingLen.getOriginalSizeInBytes() + 32 + 32);
        buf.put(mappingLen.encode());
        buf.put(keysTree.getRoot());
        buf.put(valuesTree.getRoot());
        return buf.array();
    }

    public static MerkleTree buildTree(List<byte[]> elements) {
        return new MerkleTree(elements);
    }

    public static Sha256Hash getMerkleRoot(List<byte[]> elements) {
        return buildTree(elements).getRootHash();
    }

    // Helper Functions
    public static int floorLg(int n) {
        if(n <= 0) {
            throw new IllegalArgumentException("Input must be positive.");
        }
        int r = 0;
        int t = 1;
        while(2 * t <= n) {
            t = 2 * t;
            r = r + 1;
        }
        return r;
    }

    public static int ceilLg(int n) {
        if(n <= 0) {
            throw new IllegalArgumentException("Input must be positive.");
        }
        int r = 0;
        int t = 1;
        while(t < n) {
            t = t * 2;
            r = r + 1;
        }
        return r;
    }

    public static boolean isPowerOf2(int n) {
        return n >= 1 && (n & (n - 1)) == 0;
    }

    public static int largestPowerOf2LessThan(int n) {
        if(n <= 1) {
            throw new IllegalArgumentException("Input must be greater than 1.");
        }
        if(isPowerOf2(n)) {
            return n / 2;
        } else {
            return 1 << floorLg(n);
        }
    }

    public static byte[] combineHashes(byte[] left, byte[] right) {
        if(left.length != 32 || right.length != 32) {
            throw new IllegalArgumentException("The elements must be 32 bytes sha256 outputs.");
        }
        byte[] data = new byte[65];
        data[0] = 0x01;
        System.arraycopy(left, 0, data, 1, 32);
        System.arraycopy(right, 0, data, 33, 32);
        return Sha256Hash.hash(data);
    }

    // Node Class
    public static class Node {
        Node left, right, parent;
        byte[] value;

        public Node(Node left, Node right, Node parent, byte[] value) {
            this.left = left;
            this.right = right;
            this.parent = parent;
            this.value = value;
        }

        public void recomputeValue() {
            if(left == null || right == null) {
                throw new AssertionError("Left and right children must not be null.");
            }
            this.value = combineHashes(left.value, right.value);
        }

        public Node sibling() {
            if(parent == null) {
                throw new IndexOutOfBoundsException("The root does not have a sibling.");
            }
            if(parent.left == this) {
                return parent.right;
            } else if(parent.right == this) {
                return parent.left;
            } else {
                throw new IndexOutOfBoundsException("Invalid state: not a child of its parent.");
            }
        }
    }

    // Merkle Tree building routine
    public static Node makeTree(List<Node> leaves, int begin, int size) {
        if(size == 0) {
            return null;
        }
        if(size == 1) {
            return leaves.get(begin);
        }

        int lchildSize = largestPowerOf2LessThan(size);
        Node lchild = makeTree(leaves, begin, lchildSize);
        Node rchild = makeTree(leaves, begin + lchildSize, size - lchildSize);
        Node root = new Node(lchild, rchild, null, null);
        root.recomputeValue();
        lchild.parent = rchild.parent = root;
        return root;
    }

    // Merkle Tree Class
    public static class MerkleTree {
        private final List<Node> leaves;
        private Node rootNode;
        private int depth;

        public MerkleTree(Iterable<byte[]> elements) {
            leaves = new ArrayList<>();
            for(byte[] el : elements) {
                leaves.add(new Node(null, null, null, el));
            }
            int nElements = leaves.size();
            if(nElements > 0) {
                rootNode = makeTree(leaves, 0, nElements);
                depth = ceilLg(nElements);
            } else {
                rootNode = null;
                depth = 0;
            }
        }

        public int size() {
            return leaves.size();
        }

        public byte[] getRoot() {
            return rootNode == null ? Sha256Hash.ZERO_HASH.getBytes() : rootNode.value;
        }

        public Sha256Hash getRootHash() {
            return Sha256Hash.wrap(getRoot());
        }

        public MerkleTree copy() {
            List<byte[]> newLeaves = new ArrayList<>();
            for(Node leaf : leaves) {
                newLeaves.add(leaf.value);
            }
            return new MerkleTree(newLeaves);
        }

        public void add(byte[] x) {
            if(x.length != 32) {
                throw new IllegalArgumentException("Inserted elements must be exactly 32 bytes long.");
            }
            Node newLeaf = new Node(null, null, null, x);
            leaves.add(newLeaf);
            if(leaves.size() == 1) {
                rootNode = newLeaf;
                depth = 0;
                return;
            }

            Node curRoot = rootNode;
            int curRootSize = leaves.size() - 1;
            int ltreeSize = depth == 0 ? 0 : (1 << (depth - 1));

            while(!isPowerOf2(curRootSize)) {
                curRoot = curRoot.right;
                curRootSize -= ltreeSize;
                ltreeSize /= 2;
            }

            Node newNode = new Node(curRoot, newLeaf, curRoot.parent, null);
            if(curRoot.parent == null) {
                depth += 1;
                rootNode = newNode;
            } else {
                assert curRoot.parent.right == curRoot;
                curRoot.parent.right = newNode;
            }
            curRoot.parent = newNode;
            newLeaf.parent = newNode;
            fixUp(newNode);
        }

        public void set(int index, byte[] x) {
            if(!(0 <= index && index <= leaves.size())) {
                throw new IllegalArgumentException("Index must be at least 0 and at most the current number of leaves.");
            }

            if(x.length != 32) {
                throw new IllegalArgumentException("Inserted elements must be exactly 32 bytes long.");
            }

            if(index == leaves.size()) {
                add(x);
            } else {
                leaves.get(index).value = x;
                fixUp(leaves.get(index).parent);
            }
        }

        public void fixUp(Node node) {
            while(node != null) {
                node.recomputeValue();
                node = node.parent;
            }
        }

        public byte[] get(int i) {
            return leaves.get(i).value;
        }

        public int leafIndex(byte[] x) {
            for(int idx = 0; idx < leaves.size(); idx++) {
                if(Arrays.equals(leaves.get(idx).value, x)) {
                    return idx;
                }
            }
            throw new IllegalArgumentException("Leaf not found");
        }

        public List<byte[]> proveLeaf(int index) {
            Node node = leaves.get(index);
            List<byte[]> proof = new ArrayList<>();
            while(node.parent != null) {
                Node sibling = node.sibling();
                assert sibling != null;
                proof.add(sibling.value);
                node = node.parent;
            }
            return proof;
        }
    }
}
