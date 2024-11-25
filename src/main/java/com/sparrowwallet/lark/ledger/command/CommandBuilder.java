package com.sparrowwallet.lark.ledger.command;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.VarInt;
import com.sparrowwallet.drongo.psbt.PSBTEntry;
import com.sparrowwallet.lark.ledger.APDUCommand;
import com.sparrowwallet.lark.ledger.MerkleUtils;
import com.sparrowwallet.lark.ledger.wallet.WalletPolicy;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class CommandBuilder {
    public static final int CLA_DEFAULT = 0xB0;
    public static final int CLA_BITCOIN = 0xE1;
    public static final int CLA_FRAMEWORK = 0xF8;
    public static final int P1 = 0;
    public static final int CURRENT_PROTOCOL_VERSION = 1;

    public static APDUCommand getMasterFingerprint() {
        return new APDUCommand(CLA_BITCOIN, BitcoinInsType.GET_MASTER_FINGERPRINT.getValue(), P1, CURRENT_PROTOCOL_VERSION, new byte[0]);
    }

    public static APDUCommand getExtendedPubkey(String path, boolean display) {
        List<byte[]> keypath = getBip32Path(path);

        ByteBuffer cdata = ByteBuffer.allocate(1 + 1 + keypath.size() * 4);
        cdata.put(display ? (byte)1 : (byte)0);
        cdata.put((byte)keypath.size());
        keypath.forEach(cdata::put);

        return new APDUCommand(CLA_BITCOIN, BitcoinInsType.GET_EXTENDED_PUBKEY.getValue(), P1, CURRENT_PROTOCOL_VERSION, cdata.array());
    }

    public static APDUCommand signPsbt(List<PSBTEntry> globalEntries,
                                       List<List<PSBTEntry>> inputEntryLists, List<List<PSBTEntry>> outputEntryLists,
                                       WalletPolicy walletPolicy, Sha256Hash walletHmac) {
        byte[] globalMapCommitment = MerkleUtils.getMerkleizedMapCommitment(globalEntries);

        VarInt inputLen = new VarInt(inputEntryLists.size());
        Sha256Hash inputsRoot = MerkleUtils.getMerkleRoot(inputEntryLists.stream()
                .map(entries -> MerkleUtils.hashElement(MerkleUtils.getMerkleizedMapCommitment(entries)).getBytes()).toList());

        VarInt outputLen = new VarInt(outputEntryLists.size());
        Sha256Hash outputsRoot = MerkleUtils.getMerkleRoot(outputEntryLists.stream()
                .map(entries -> MerkleUtils.hashElement(MerkleUtils.getMerkleizedMapCommitment(entries)).getBytes()).toList());

        ByteBuffer buf = ByteBuffer.allocate(globalMapCommitment.length +
                inputLen.getOriginalSizeInBytes() + inputsRoot.getBytes().length +
                outputLen.getOriginalSizeInBytes() + outputsRoot.getBytes().length + 32 + 32);
        buf.put(globalMapCommitment);
        buf.put(inputLen.encode());
        buf.put(inputsRoot.getBytes());
        buf.put(outputLen.encode());
        buf.put(outputsRoot.getBytes());
        buf.put(walletPolicy.id().getBytes());
        buf.put(walletHmac == null ? new byte[32] : walletHmac.getBytes());

        return new APDUCommand(CLA_BITCOIN, BitcoinInsType.SIGN_PSBT.getValue(), P1, CURRENT_PROTOCOL_VERSION, buf.array());
    }

    public static APDUCommand registerWallet(WalletPolicy walletPolicy) {
        byte[] walletPolicyBytes = walletPolicy.serialize();
        VarInt policyLen = new VarInt(walletPolicyBytes.length);
        ByteBuffer buf = ByteBuffer.allocate(policyLen.getOriginalSizeInBytes() + walletPolicyBytes.length);
        buf.put(policyLen.encode());
        buf.put(walletPolicyBytes);

        return new APDUCommand(CLA_BITCOIN, BitcoinInsType.REGISTER_WALLET.getValue(), P1, CURRENT_PROTOCOL_VERSION, buf.array());
    }

    public static APDUCommand signMessage(String message, String path) {
        List<byte[]> keypath = getBip32Path(path);
        List<byte[]> chunks = splitIntoChunks(message.getBytes());
        VarInt messageLen = new VarInt(message.length());
        Sha256Hash root = MerkleUtils.getMerkleRoot(chunks.stream().map(chunk -> MerkleUtils.hashElement(chunk).getBytes()).toList());

        ByteBuffer buf = ByteBuffer.allocate(1 + keypath.size() * 4 + messageLen.getOriginalSizeInBytes() + 32);
        buf.put((byte)keypath.size());
        keypath.forEach(buf::put);
        buf.put(messageLen.encode());
        buf.put(root.getBytes());

        return new APDUCommand(CLA_BITCOIN, BitcoinInsType.SIGN_MESSAGE.getValue(), P1, CURRENT_PROTOCOL_VERSION, buf.array());
    }

    public static APDUCommand getWalletAddress(WalletPolicy walletPolicy, Sha256Hash walletHmac, int addressIndex, int change, boolean display) {
        ByteBuffer buf = ByteBuffer.allocate(1 + 32 + 32 + 1 + 4);
        buf.put(display ? (byte)1 : (byte)0);
        buf.put(walletPolicy.id().getBytes());
        buf.put(walletHmac == null ? new byte[32] : walletHmac.getBytes());
        buf.put((byte)change);
        buf.putInt(addressIndex);

        return new APDUCommand(CLA_BITCOIN, BitcoinInsType.GET_WALLET_ADDRESS.getValue(), P1, CURRENT_PROTOCOL_VERSION, buf.array());
    }

    private static List<byte[]> getBip32Path(String path) {
        return KeyDerivation.parsePath(path).stream().map(ChildNumber::i).map(i -> {
            ByteBuffer buf = ByteBuffer.allocate(4);
            buf.putInt(i);
            return buf.array();
        }).toList();
    }

    public static List<byte[]> splitIntoChunks(byte[] messageBytes) {
        List<byte[]> chunks = new ArrayList<>();
        int chunkSize = 64;
        int numChunks = (messageBytes.length + chunkSize - 1) / chunkSize;

        for(int i = 0; i < numChunks; i++) {
            int start = i * chunkSize;
            int end = Math.min(start + chunkSize, messageBytes.length);

            byte[] chunk = new byte[end - start];
            System.arraycopy(messageBytes, start, chunk, 0, end - start);

            chunks.add(chunk);
        }

        return chunks;
    }

    public static APDUCommand continueInterrupted(byte[] cdata) {
        return new APDUCommand(CLA_FRAMEWORK, FrameworkInsType.CONTINUE_INTERRUPTED.getValue(), P1, CURRENT_PROTOCOL_VERSION, cdata);
    }
}
