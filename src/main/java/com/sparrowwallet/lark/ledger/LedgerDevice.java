package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.protocol.VarInt;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.Version;
import com.sparrowwallet.lark.ledger.command.CommandBuilder;
import com.sparrowwallet.lark.ledger.command.DefaultInsType;
import com.sparrowwallet.lark.ledger.wallet.MultisigWalletPolicy;
import com.sparrowwallet.lark.ledger.wallet.WalletPolicy;

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public abstract class LedgerDevice implements Closeable {
    protected final Transport transport;

    public LedgerDevice(Transport transport) {
        this.transport = transport;
    }

    /**
     * Queries the hardware wallet for the currently running app's name, version and state flags.
     *
     * @return the LedgerVersion object
     * @throws DeviceException on an error
     */
    public LedgerVersion getVersion() throws DeviceException {
        Transport.Response response = makeRequest(new APDUCommand(CommandBuilder.CLA_DEFAULT, DefaultInsType.GET_VERSION.getValue(), 0, 0, new byte[0]));

        if(response.sw() != 0x9000) {
            throw new LedgerResponseException(response, DefaultInsType.GET_VERSION);
        }

        String name = "";
        Version version = null;
        byte[] flags = new byte[0];

        byte[] data = response.data();
        int cursor = 0;

        byte format = data[0];
        cursor++;

        try {
            VarInt nameLen = new VarInt(data, cursor);
            cursor += nameLen.getOriginalSizeInBytes();
            name = new String(data, cursor, cursor + (int)nameLen.value, StandardCharsets.UTF_8);
            cursor += (int)nameLen.value;
        } catch(Exception e) {
            //ignore
        }

        try {
            VarInt verLen = new VarInt(data, cursor);
            cursor += verLen.getOriginalSizeInBytes();
            String ver = new String(data, cursor, (int)verLen.value, StandardCharsets.UTF_8);
            version = new Version(ver);
            cursor += (int)verLen.value;
        } catch(Exception e) {
            //ignore
        }

        try {
            VarInt flagsLen = new VarInt(data, cursor);
            cursor += flagsLen.getOriginalSizeInBytes();
            flags = Arrays.copyOfRange(data, cursor, cursor + (int)flagsLen.value);
        } catch(Exception e) {
            //ignore
        }

        if(format != 0x01 || name.isEmpty() || version == null) {
            throw new DeviceException("Invalid format returned by GET_VERSION");
        }

        return new LedgerVersion(name, version, flags);
    }

    public abstract String getMasterFingerprint() throws DeviceException;

    public abstract ExtendedKey getExtendedPubkey(String path, boolean display) throws DeviceException;

    public abstract List<Signature> signPsbt(PSBT psbt, WalletPolicy walletPolicy, Sha256Hash walletHmac) throws DeviceException;

    public abstract WalletRegistration registerWallet(WalletPolicy walletPolicy) throws DeviceException;

    public abstract String signMessage(String message, String path) throws DeviceException;

    public abstract String getWalletAddress(WalletPolicy walletPolicy, Sha256Hash walletHmac, int change, int addressIndex, boolean display) throws DeviceException;

    protected Transport.Response makeRequest(APDUCommand apduCommand) throws DeviceException {
        try {
            return transport.apduExchange(apduCommand);
        } catch(LedgerTransportException e) {
            return e.getResponse();
        }
    }

    @Override
    public void close() {
        try {
            transport.close();
        } catch(IOException e) {
            throw new RuntimeException(e);
        }
    }

    public record LedgerVersion(String name, Version version, byte[] state) {
        public boolean isLegacy() {
            return version.compareTo(new Version("2.0.99")) < 0 || name.contains("Legacy");
        }
    }

    public record Signature(int inputIndex, ECKey ecKey, TransactionSignature transactionSignature) {}
    public record WalletRegistration(Sha256Hash id, Sha256Hash hmac) {}
}
