package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTEntry;
import com.sparrowwallet.drongo.psbt.PSBTParseException;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.ledger.command.BitcoinInsType;
import com.sparrowwallet.lark.ledger.command.ClientCommandInterpreter;
import com.sparrowwallet.lark.ledger.command.CommandBuilder;
import com.sparrowwallet.lark.ledger.wallet.WalletPolicy;

import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

public class NewLedgerDevice extends LedgerDevice {
    public NewLedgerDevice(Transport transport) {
        super(transport);
    }

    public String getMasterFingerprint() throws DeviceException {
        Transport.Response response = makeRequest(CommandBuilder.getMasterFingerprint());
        if(response.sw() != 0x9000) {
            throw new LedgerResponseException(response, BitcoinInsType.GET_MASTER_FINGERPRINT);
        }

        return Utils.bytesToHex(response.data());
    }

    public ExtendedKey getExtendedPubkey(String path, boolean display) throws DeviceException {
        Transport.Response response = makeRequest(CommandBuilder.getExtendedPubkey(path, display));
        if(response.sw() != 0x9000) {
            throw new LedgerResponseException(response, BitcoinInsType.GET_EXTENDED_PUBKEY);
        }

        return ExtendedKey.fromDescriptor(new String(response.data()));
    }

    /**
     * Signs a PSBT using a registered wallet (or a standard wallet that does not need registration).
     * Signature requires explicit approval from the user.
     *
     * @param psbt         A PSBT of version 0 or 2, with all the necessary information to sign the inputs already filled in; what the
     *                     required fields changes depending on the type of input.
     *                     The non-witness UTXO must be present for both legacy and SegWit inputs, or the hardware wallet will reject
     *                     signing. This is not required for Taproot inputs.
     * @param walletPolicy The registered wallet policy, or a standard wallet policy.
     * @param walletHmac   For a registered wallet, the hmac obtained at wallet registration. `None` for a standard wallet policy.
     * @return A map of pubkeys and signatures
     * @throws DeviceException on an error
     */
    @Override
    public List<Signature> signPsbt(PSBT psbt, WalletPolicy walletPolicy, Sha256Hash walletHmac) throws DeviceException {
        try {
            PSBTEntryParser psbtEntryParser = new PSBTEntryParser(psbt);

            ClientCommandInterpreter clientInterpreter = new ClientCommandInterpreter();
            clientInterpreter.addKnownList(walletPolicy.getKeysInfo().stream().map(str -> str.getBytes(StandardCharsets.ISO_8859_1)).toList());
            clientInterpreter.addKnownPreimage(walletPolicy.serialize());

            // necessary for version 1 of the protocol (available since version 2.1.0 of the app)
            clientInterpreter.addKnownPreimage(walletPolicy.getDescriptorTemplate().getBytes(StandardCharsets.ISO_8859_1));

            clientInterpreter.addKnownMapping(psbtEntryParser.getGlobalEntries().stream().collect(Collectors.toMap(PSBTEntry::getKey, PSBTEntry::getData)));
            for(List<PSBTEntry> inputEntries : psbtEntryParser.getInputEntryLists()) {
                clientInterpreter.addKnownMapping(inputEntries.stream().collect(Collectors.toMap(PSBTEntry::getKey, PSBTEntry::getData)));
            }
            for(List<PSBTEntry> outputEntries : psbtEntryParser.getOutputEntryLists()) {
                clientInterpreter.addKnownMapping(outputEntries.stream().collect(Collectors.toMap(PSBTEntry::getKey, PSBTEntry::getData)));
            }

            // We also add the Merkle tree of the input (resp. output) map commitments as a known tree

            List<byte[]> inputCommitments = psbtEntryParser.getInputEntryLists().stream().map(MerkleUtils::getMerkleizedMapCommitment).toList();
            List<byte[]> outputCommitments = psbtEntryParser.getOutputEntryLists().stream().map(MerkleUtils::getMerkleizedMapCommitment).toList();

            clientInterpreter.addKnownList(inputCommitments);
            clientInterpreter.addKnownList(outputCommitments);

            Transport.Response response = makeRequest(CommandBuilder.signPsbt(psbtEntryParser.getGlobalEntries(),
                    psbtEntryParser.getInputEntryLists(), psbtEntryParser.getOutputEntryLists(), walletPolicy, walletHmac), clientInterpreter);
            if(response.sw() != 0x9000) {
                throw new LedgerResponseException(response, BitcoinInsType.SIGN_PSBT);
            }

            // parse results and return a structured version instead
            List<byte[]> results = clientInterpreter.getYielded();

            if(results.stream().anyMatch(result -> result.length <= 1)) {
                throw new DeviceException("Invalid response from SIGN_PSBT");
            }

            List<Signature> signatures = new ArrayList<>();
            for(byte[] result : results) {
                ByteStreamParser byteStreamParser = new ByteStreamParser(result);
                long inputIndex = byteStreamParser.readVarint();

                long pubkeyLen = byteStreamParser.readUint(1, ByteOrder.LITTLE_ENDIAN);
                byte[] pubkey = byteStreamParser.readBytes((int)pubkeyLen);
                ECKey ecKey = ECKey.fromPublicOnly(pubkey);

                byte[] signature = byteStreamParser.readRemaining();
                TransactionSignature transactionSignature = TransactionSignature.decodeFromBitcoin(signature, false);

                signatures.add(new Signature((int)inputIndex, ecKey, transactionSignature));
            }

            return signatures;
        } catch(PSBTParseException e) {
            throw new DeviceException("Could not parse PSBT", e);
        } catch(IOException e) {
            throw new DeviceException("Could not parse response", e);
        }
    }

    @Override
    public WalletRegistration registerWallet(WalletPolicy walletPolicy) throws DeviceException {
        ClientCommandInterpreter clientInterpreter = new ClientCommandInterpreter();
        clientInterpreter.addKnownPreimage(walletPolicy.serialize());
        clientInterpreter.addKnownList(walletPolicy.getKeysInfo().stream().map(str -> str.getBytes(StandardCharsets.ISO_8859_1)).toList());

        // necessary for version 1 of the protocol (available since version 2.1.0 of the app)
        clientInterpreter.addKnownPreimage(walletPolicy.getDescriptorTemplate().getBytes(StandardCharsets.ISO_8859_1));

        Transport.Response response = makeRequest(CommandBuilder.registerWallet(walletPolicy), clientInterpreter);
        if(response.sw() != 0x9000) {
            throw new LedgerResponseException(response, BitcoinInsType.REGISTER_WALLET);
        }

        if(response.data().length != 64) {
            throw new DeviceException("Invalid response length from REGISTER_WALLET: " + response.data().length);
        }

        return new WalletRegistration(Sha256Hash.wrap(Arrays.copyOfRange(response.data(), 0, 32)), Sha256Hash.wrap(Arrays.copyOfRange(response.data(), 32, 64)));
    }

    @Override
    public String signMessage(String message, String path) throws DeviceException {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        List<byte[]> chunks = CommandBuilder.splitIntoChunks(messageBytes);

        ClientCommandInterpreter clientInterpreter = new ClientCommandInterpreter();
        clientInterpreter.addKnownList(chunks);

        Transport.Response response = makeRequest(CommandBuilder.signMessage(message, path), clientInterpreter);
        if(response.sw() != 0x9000) {
            throw new LedgerResponseException(response, BitcoinInsType.REGISTER_WALLET);
        }

        return Base64.getEncoder().encodeToString(response.data());
    }

    @Override
    public String getWalletAddress(WalletPolicy walletPolicy, Sha256Hash walletHmac, int change, int addressIndex, boolean display) throws DeviceException {
        if(change != 0 && change != 1) {
            throw new IllegalArgumentException("Invalid change index: " + change);
        }

        ClientCommandInterpreter clientInterpreter = new ClientCommandInterpreter();
        clientInterpreter.addKnownList(walletPolicy.getKeysInfo().stream().map(str -> str.getBytes(StandardCharsets.ISO_8859_1)).toList());
        clientInterpreter.addKnownPreimage(walletPolicy.serialize());

        // necessary for version 1 of the protocol (available since version 2.1.0 of the app)
        clientInterpreter.addKnownPreimage(walletPolicy.getDescriptorTemplate().getBytes(StandardCharsets.ISO_8859_1));

        Transport.Response response = makeRequest(CommandBuilder.getWalletAddress(walletPolicy, walletHmac, addressIndex, change, display), clientInterpreter);
        if(response.sw() != 0x9000) {
            throw new LedgerResponseException(response, BitcoinInsType.GET_WALLET_ADDRESS);
        }

        return new String(response.data(), StandardCharsets.UTF_8);
    }

    @Override
    protected Transport.Response makeRequest(APDUCommand apduCommand) throws DeviceException {
        return makeRequest(apduCommand, null);
    }

    protected Transport.Response makeRequest(APDUCommand apduCommand, ClientCommandInterpreter clientInterpreter) throws DeviceException {
        Transport.Response response;
        try {
            response = transport.apduExchange(apduCommand);
        } catch(LedgerTransportException e) {
            response = e.getResponse();
        }

        while(response.sw() == 0xE000) {
            if(clientInterpreter == null) {
                throw new DeviceException("Unexpected SW_INTERRUPTED_EXECUTION received");
            }

            byte[] commandResponse = clientInterpreter.execute(response.data());
            try {
                response = transport.apduExchange(CommandBuilder.continueInterrupted(commandResponse));
            } catch(LedgerTransportException e) {
                response = e.getResponse();
            }
        }

        return response;
    }
}
