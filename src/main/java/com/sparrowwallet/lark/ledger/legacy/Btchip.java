package com.sparrowwallet.lark.ledger.legacy;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.Version;
import com.sparrowwallet.lark.ledger.APDUCommand;
import com.sparrowwallet.lark.ledger.LedgerDevice;
import com.sparrowwallet.lark.ledger.LedgerTransportException;
import com.sparrowwallet.lark.ledger.Transport;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Btchip {
    // Class codes
    private static final byte BTCHIP_CLA = (byte) 0xe0;
    private static final byte BTCHIP_CLA_COMMON_SDK = (byte) 0xb0;
    private static final byte BTCHIP_JC_EXT_CLA = (byte) 0xf0;

    // Instruction codes
    private static final byte BTCHIP_INS_GET_APP_NAME_AND_VERSION = (byte) 0x01;
    private static final byte BTCHIP_INS_SET_ALTERNATE_COIN_VERSION = (byte) 0x14;
    private static final byte BTCHIP_INS_SETUP = (byte) 0x20;
    private static final byte BTCHIP_INS_VERIFY_PIN = (byte) 0x22;
    private static final byte BTCHIP_INS_GET_OPERATION_MODE = (byte) 0x24;
    private static final byte BTCHIP_INS_SET_OPERATION_MODE = (byte) 0x26;
    private static final byte BTCHIP_INS_SET_KEYMAP = (byte) 0x28;
    private static final byte BTCHIP_INS_SET_COMM_PROTOCOL = (byte) 0x2a;
    private static final byte BTCHIP_INS_GET_WALLET_PUBLIC_KEY = (byte) 0x40;
    private static final byte BTCHIP_INS_GET_TRUSTED_INPUT = (byte) 0x42;
    private static final byte BTCHIP_INS_HASH_INPUT_START = (byte) 0x44;
    private static final byte BTCHIP_INS_HASH_INPUT_FINALIZE = (byte) 0x46;
    private static final byte BTCHIP_INS_HASH_SIGN = (byte) 0x48;
    private static final byte BTCHIP_INS_HASH_INPUT_FINALIZE_FULL = (byte) 0x4a;
    private static final byte BTCHIP_INS_GET_INTERNAL_CHAIN_INDEX = (byte) 0x4c;
    private static final byte BTCHIP_INS_SIGN_MESSAGE = (byte) 0x4e;
    private static final byte BTCHIP_INS_GET_TRANSACTION_LIMIT = (byte) 0xa0;
    private static final byte BTCHIP_INS_SET_TRANSACTION_LIMIT = (byte) 0xa2;
    private static final byte BTCHIP_INS_IMPORT_PRIVATE_KEY = (byte) 0xb0;
    private static final byte BTCHIP_INS_GET_PUBLIC_KEY = (byte) 0xb2;
    private static final byte BTCHIP_INS_DERIVE_BIP32_KEY = (byte) 0xb4;
    private static final byte BTCHIP_INS_SIGNVERIFY_IMMEDIATE = (byte) 0xb6;
    private static final byte BTCHIP_INS_GET_RANDOM = (byte) 0xc0;
    private static final byte BTCHIP_INS_GET_ATTESTATION = (byte) 0xc2;
    private static final byte BTCHIP_INS_GET_FIRMWARE_VERSION = (byte) 0xc4;
    private static final byte BTCHIP_INS_COMPOSE_MOFN_ADDRESS = (byte) 0xc6;
    private static final byte BTCHIP_INS_GET_POS_SEED = (byte) 0xca;

    // Extended instruction codes
    private static final byte BTCHIP_INS_EXT_GET_HALF_PUBLIC_KEY = (byte) 0x20;
    private static final byte BTCHIP_INS_EXT_CACHE_PUT_PUBLIC_KEY = (byte) 0x22;
    private static final byte BTCHIP_INS_EXT_CACHE_HAS_PUBLIC_KEY = (byte) 0x24;
    private static final byte BTCHIP_INS_EXT_CACHE_GET_FEATURES = (byte) 0x26;

    // Operation modes
    private static final byte OPERATION_MODE_WALLET = (byte) 0x01;
    private static final byte OPERATION_MODE_RELAXED_WALLET = (byte) 0x02;
    private static final byte OPERATION_MODE_SERVER = (byte) 0x04;
    private static final byte OPERATION_MODE_DEVELOPER = (byte) 0x08;

    // Features
    private static final byte FEATURE_UNCOMPRESSED_KEYS = (byte) 0x01;
    private static final byte FEATURE_RFC6979 = (byte) 0x02;
    private static final byte FEATURE_FREE_SIGHASHTYPE = (byte) 0x04;
    private static final byte FEATURE_NO_2FA_P2SH = (byte) 0x08;

    private final Transport transport;
    private final int scriptBlockLength;

    public Btchip(Transport transport, LedgerDevice.LedgerVersion ledgerVersion) {
        this.transport = transport;
        if(ledgerVersion.version().compareTo(new Version("1.1.4")) >= 0) {
            scriptBlockLength = 50;
        } else {
            scriptBlockLength = 255;
        }
    }

    public Map<String, byte[]> getWalletPublicKey(String path) throws DeviceException {
        return getWalletPublicKey(path, false, false, false, false);
    }

    public Map<String, byte[]> getWalletPublicKey(String path, boolean showOnScreen) throws DeviceException {
        return getWalletPublicKey(path, showOnScreen, false, false, false);
    }

    public Map<String, byte[]> getWalletPublicKey(String path, boolean showOnScreen, boolean segwit, boolean segwitNative, boolean cashAddr) throws DeviceException {
        Map<String, byte[]> result = new HashMap<>();
        byte[] pathBytes = parseBip32Path(path);
        APDUCommand apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_GET_WALLET_PUBLIC_KEY, showOnScreen ? 1 : 0, cashAddr ? 3 : (segwitNative ? 2 : (segwit ? 1 : 0)), pathBytes);
        byte[] response = transport.apduExchange(apduCommand).data();
        int offset = 0;

        // Extract the public key
        int publicKeyLength = response[offset];
        byte[] publicKey = new byte[publicKeyLength];
        System.arraycopy(response, offset + 1, publicKey, 0, publicKeyLength);
        result.put("publicKey", publicKey);
        offset = offset + 1 + publicKeyLength;

        // Extract the address
        int addressLength = response[offset];
        String address = new String(response, offset + 1, addressLength, StandardCharsets.UTF_8);
        result.put("address", address.getBytes(StandardCharsets.UTF_8));
        offset = offset + 1 + addressLength;

        // Extract the chain code
        byte[] chainCode = new byte[32];
        System.arraycopy(response, offset, chainCode, 0, 32);
        result.put("chainCode", chainCode);

        return result;
    }

    public Map<String, Object> getTrustedInput(Transaction transaction, long index) throws DeviceException {
        Map<String, Object> result = new LinkedHashMap<>();

        // Header
        byte[] versionBytes = new byte[4];
        Utils.uint32ToByteArrayLE(transaction.getVersion(), versionBytes, 0);
        VarInt inputsLen = new VarInt(transaction.getInputs().size());
        ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + inputsLen.getOriginalSizeInBytes());
        buffer.put(Utils.hexToBytes(String.format("%08x", index)));
        buffer.put(versionBytes);
        buffer.put(inputsLen.encode());
        APDUCommand apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0, 0, buffer.array());
        transport.apduExchange(apduCommand);

        // Each input
        for(TransactionInput input : transaction.getInputs()) {
            byte[] prevOut = input.getOutpoint().bitcoinSerialize();
            VarInt scriptLen = new VarInt(input.getScriptBytes().length);
            ByteBuffer buf = ByteBuffer.allocate(prevOut.length + scriptLen.getOriginalSizeInBytes());
            buf.put(prevOut);
            buf.put(scriptLen.encode());
            apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0, buf.array());
            transport.apduExchange(apduCommand);

            int offset = 0;
            do {
                int blockLength = 251;
                int dataLength;
                if((offset + blockLength) < input.getScriptBytes().length) {
                    dataLength = blockLength;
                } else {
                    dataLength = input.getScriptBytes().length - offset;
                }
                byte[] data = Arrays.copyOfRange(input.getScriptBytes(), offset, offset + dataLength);
                if((offset + dataLength) == input.getScriptBytes().length) {
                    byte[] seqBytes = new byte[4];
                    Utils.uint32ToByteArrayLE(input.getSequenceNumber(), seqBytes, 0);
                    data = Utils.concat(data, seqBytes);
                }
                apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0, data);
                transport.apduExchange(apduCommand);
                offset += dataLength;
            } while(offset < input.getScriptBytes().length);
        }

        //Number of outputs
        VarInt outputsLen = new VarInt(transaction.getOutputs().size());
        buffer = ByteBuffer.allocate(outputsLen.getOriginalSizeInBytes());
        buffer.put(outputsLen.encode());
        apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0, buffer.array());
        transport.apduExchange(apduCommand);

        //Each output
        int indexOutput = 0;
        for(TransactionOutput output : transaction.getOutputs()) {
            byte[] valueBytes = new byte[8];
            Utils.int64ToByteArrayLE(output.getValue(), valueBytes, 0);
            VarInt scriptLen = new VarInt(output.getScriptBytes().length);
            ByteBuffer buf = ByteBuffer.allocate(valueBytes.length + scriptLen.getOriginalSizeInBytes());
            buf.put(valueBytes);
            buf.put(scriptLen.encode());
            apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0, buf.array());
            transport.apduExchange(apduCommand);
            int offset = 0;
            while(offset < output.getScriptBytes().length) {
                int blockLength = 255;
                int dataLength;
                if((offset + blockLength) < output.getScriptBytes().length) {
                    dataLength = blockLength;
                } else {
                    dataLength = output.getScriptBytes().length - offset;
                }
                byte[] data = Arrays.copyOfRange(output.getScriptBytes(), offset, offset + dataLength);
                apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0, data);
                transport.apduExchange(apduCommand);
                offset += dataLength;
            }
        }

        // Locktime
        byte[] locktimeBytes = new byte[4];
        Utils.uint32ToByteArrayLE(transaction.getLocktime(), locktimeBytes, 0);
        apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0, locktimeBytes);
        Transport.Response response = transport.apduExchange(apduCommand);

        result.put("trustedInput", Boolean.TRUE);
        result.put("value", response.data());
        return result;
    }

    public void startUntrustedTransaction(boolean newTransaction, int inputIndex, List<Map<String, Object>> outputList, Script redeemScript, long version) throws DeviceException {
        startUntrustedTransaction(newTransaction, inputIndex, outputList, redeemScript, version, false, false);
    }

    public void startUntrustedTransaction(boolean newTransaction, int inputIndex, List<Map<String, Object>> outputList, Script redeemScript, long version,
                                          boolean cashAddr, boolean continueSegwit) throws DeviceException {
        boolean segwit = false;
        if(newTransaction) {
            for(Map<String, Object> output : outputList) {
                if(output.containsKey("witness") && output.get("witness") != null) {
                    segwit = true;
                    break;
                }
            }
        }
        int p2;
        if(newTransaction) {
            if(segwit) {
                p2 = cashAddr ? 0x03 : 0x02;
            } else {
                p2 = 0x00;
            }
        } else {
            p2 = continueSegwit ? 0x10 : 0x80;
        }
        VarInt outputsLen = new VarInt(outputList.size());
        ByteBuffer buf = ByteBuffer.allocate(4 + outputsLen.getOriginalSizeInBytes());
        buf.put(new byte[] { (byte)version, 0x00, 0x00, 0x00 });
        buf.put(outputsLen.encode());
        APDUCommand apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_HASH_INPUT_START, 0, p2, buf.array());
        transport.apduExchange(apduCommand);

        // Loop for each input
        int currentIndex = 0;
        for(Map<String, Object> output : outputList) {
            byte[] seqBytes;
            if(output.containsKey("sequence") && output.get("sequence") != null) {
                seqBytes = Utils.hexToBytes(output.get("sequence").toString());
            } else {
                seqBytes = new byte[] { (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF };
            }

            Script script = redeemScript;
            if(currentIndex != inputIndex) {
                script = new Script(new byte[0]);
            }

            byte[] value = (output.get("trustedInput") != null ? (byte[])output.get("value") : new byte[0]);
            VarInt scriptLen = new VarInt(script.getProgram().length);
            buf = ByteBuffer.allocate(1 + 1 + value.length + scriptLen.getOriginalSizeInBytes());
            if(output.get("trustedInput") != null) {
                buf.put((byte)0x01);
            } else if(output.get("witness") != null) {
                buf.put((byte)0x02);
            } else {
                buf.put((byte)0x00);
            }
            buf.put((byte)value.length);
            buf.put(value);
            buf.put(scriptLen.encode());
            apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_HASH_INPUT_START, 0x80, 0, buf.array());
            transport.apduExchange(apduCommand);

            int offset = 0;
            while(offset < script.getProgram().length) {
                int blockLength = 255;
                int dataLength;
                if((offset + blockLength) < script.getProgram().length) {
                    dataLength = blockLength;
                } else {
                    dataLength = script.getProgram().length - offset;
                }
                byte[] data = Arrays.copyOfRange(script.getProgram(), offset, offset + dataLength);
                if((offset + dataLength) == script.getProgram().length) {
                    data = Utils.concat(data, seqBytes);
                }
                apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_HASH_INPUT_START, 0x80, 0, data);
                transport.apduExchange(apduCommand);
                offset += blockLength;
            }

            if(script.isEmpty()) {
                apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_HASH_INPUT_START, 0x80, 0, seqBytes);
                transport.apduExchange(apduCommand);
            }

            currentIndex++;
        }
    }

    public Map<String, Object> finalizeInput(byte[] outputAddress, long amount, long fees, List<ChildNumber> changePath, Transaction rawTx) throws DeviceException {
        boolean alternateEncoding = false;
        byte[] donglePath = parseBip32Path(KeyDerivation.writePath(changePath));

        Map<String, Object> result = new LinkedHashMap<>();
        byte[] outputs = null;

        Transport.Response response = null;

        if(rawTx != null) {
            try {
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                stream.write(new VarInt(rawTx.getOutputs().size()).encode());
                for(TransactionOutput out : rawTx.getOutputs()) {
                    stream.writeBytes(out.bitcoinSerialize());
                }
                outputs = stream.toByteArray();

                if(donglePath.length != 0) {
                    APDUCommand apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_HASH_INPUT_FINALIZE_FULL, 0xFF, 0, donglePath);
                    response = transport.apduExchange(apduCommand);
                }
                int offset = 0;
                while(offset < outputs.length) {
                    int blockLength = scriptBlockLength;
                    int dataLength;
                    int p1;
                    if((offset + blockLength) < outputs.length) {
                        dataLength = blockLength;
                        p1 = 0x00;
                    } else {
                        dataLength = outputs.length - offset;
                        p1 = 0x80;
                    }
                    byte[] data = Arrays.copyOfRange(outputs, offset, offset + dataLength);
                    APDUCommand apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_HASH_INPUT_FINALIZE_FULL, p1, 0, data);
                    response = transport.apduExchange(apduCommand);
                    offset += dataLength;
                }
                alternateEncoding = true;
            } catch(Exception e) {
                //ignore
            }
        }

        if(!alternateEncoding) {
            ByteBuffer buf = ByteBuffer.allocate(1 + outputAddress.length + 8 + 8 + donglePath.length);
            buf.put((byte)outputAddress.length);
            buf.put(outputAddress);
            writeHexAmountBE(amount, buf);
            writeHexAmountBE(fees, buf);
            buf.put(donglePath);
            APDUCommand apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_HASH_INPUT_FINALIZE, 0x02, 0, buf.array());
            response = transport.apduExchange(apduCommand);
        }

        byte[] responseData = response.data();
        result.put("confirmationNeeded", responseData[1 + responseData[0]] != 0x00);
        result.put("confirmationType", responseData[1 + responseData[0]]);
        if((byte)result.get("confirmationType") == (byte)0x02) {
            result.put("keycardData", Arrays.copyOfRange(responseData, 1 + responseData[0] + 1, responseData.length));
        }
        if((byte)result.get("confirmationType") == (byte)0x03) {
            int offset = 1 + responseData[0] + 1;
            int keycardDataLength = responseData[offset];
            result.put("keycardData", Arrays.copyOfRange(responseData, offset, offset + keycardDataLength));
            offset += keycardDataLength;
            result.put("secureScreenData", Arrays.copyOfRange(responseData, offset, responseData.length));
        }
        if((byte)result.get("confirmationType") == (byte)0x04) {
            int offset = 1 + responseData[0] + 1;
            int keycardDataLength = responseData[offset];
            result.put("keycardData", Arrays.copyOfRange(responseData, offset + 1, offset + 1 + keycardDataLength));
        }
        if(outputs == null) {
            result.put("outputData", Arrays.copyOfRange(responseData, 1, 1 + responseData[0]));
        } else {
            result.put("outputData", outputs);
        }

        return result;
    }

    public byte[] untrustedHashSign(String path, String pin, long locktime, SigHash sigHash) throws DeviceException {
        byte[] pathBytes = parseBip32Path(path);
        byte[] pinBytes = pin.getBytes(StandardCharsets.UTF_8);

        ByteBuffer buf = ByteBuffer.allocate( pathBytes.length + 1 + pinBytes.length + 4 + 1);
        buf.put(pathBytes);
        buf.put((byte)pinBytes.length);
        buf.put(pinBytes);
        buf.putInt((int)locktime);
        buf.put(sigHash.value);

        APDUCommand apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_HASH_SIGN, 0, 0, buf.array());
        Transport.Response response = transport.apduExchange(apduCommand);
        byte[] responseData = response.data();
        responseData[0] = 0x30;
        return responseData;
    }

    public Map<String, Object> signMessagePrepare(String path, byte[] messageBytes) throws DeviceException {
        try {
            return signMessagePrepareV2(path, messageBytes);
        } catch(LedgerTransportException e) {
            if(e.getResponse().sw() == 0x6B00) {
                // Old firmware version, try older method
                return signMessagePrepareV1(path, messageBytes);
            }
            throw e;
        }
    }

    private Map<String, Object> signMessagePrepareV1(String path, byte[] messageBytes) throws DeviceException {
        byte[] donglePath = parseBip32Path(path);

        Map<String, Object> results = new LinkedHashMap<>();
        ByteBuffer buf = ByteBuffer.allocate(donglePath.length + 1 + messageBytes.length);
        buf.put(donglePath);
        buf.put((byte)messageBytes.length);
        buf.put(messageBytes);

        APDUCommand apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_SIGN_MESSAGE, 0, 0, buf.array());
        Transport.Response response = transport.apduExchange(apduCommand);
        byte[] responseData = response.data();
        results.put("confirmationNeeded", responseData[0] != 0);
        results.put("confirmationType", responseData[0]);
        if((byte)results.get("confirmationType") == (byte)0x02) {
            results.put("keycardData", Arrays.copyOfRange(responseData, 1, responseData.length));
        }
        if((byte)results.get("confirmationType") == (byte)0x03) {
            results.put("secureScreenData", Arrays.copyOfRange(responseData, 1, responseData.length));
        }
        return results;
    }

    private Map<String, Object> signMessagePrepareV2(String path, byte[] messageBytes) throws DeviceException {
        byte[] donglePath = parseBip32Path(path);

        Map<String, Object> results = new LinkedHashMap<>();
        int offset = 0;
        byte[] responseData = new byte[0];
        byte[] encryptedOutputData = new byte[0];

        while(offset < messageBytes.length) {
            byte[] header = new byte[0];
            int p2;
            if(offset == 0) {
                ByteBuffer buf = ByteBuffer.allocate(donglePath.length + 1 + 1);
                buf.put(donglePath);
                buf.put((byte)((messageBytes.length >> 8) & 0xFF));
                buf.put((byte)(messageBytes.length & 0xFF));
                header = buf.array();
                p2 = 0x01;
            } else {
                p2 = 0x80;
            }
            int blockLength = 255 - header.length;
            int dataLength;
            if((offset + blockLength) < messageBytes.length) {
                dataLength = blockLength;
            } else {
                dataLength = messageBytes.length - offset;
            }
            byte[] messagePart = Arrays.copyOfRange(messageBytes, offset, offset + dataLength);
            ByteBuffer buf = ByteBuffer.allocate(header.length + dataLength);
            buf.put(header);
            buf.put(messagePart);

            APDUCommand apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_SIGN_MESSAGE, 0, p2, buf.array());
            Transport.Response response = transport.apduExchange(apduCommand);
            responseData = response.data();
            encryptedOutputData = Utils.concat(encryptedOutputData, Arrays.copyOfRange(responseData, 1, 1 + responseData[0]));
            offset += dataLength;
        }

        results.put("confirmationNeeded", responseData[1 + responseData[0]] != 0x00);
        results.put("confirmationType", responseData[1 + responseData[0]]);
        if((byte)results.get("confirmationType") == (byte)0x03) {
            offset = 1 + responseData[0] + 1;
            results.put("secureScreenData", Arrays.copyOfRange(responseData, offset, responseData.length));
            results.put("encryptedOutputData", encryptedOutputData);
        }

        return results;
    }

    public byte[] signMessageSign() throws DeviceException {
        APDUCommand apduCommand = new APDUCommand(BTCHIP_CLA, BTCHIP_INS_SIGN_MESSAGE, 0x80, 0, new byte[1]);
        Transport.Response response = transport.apduExchange(apduCommand);
        return response.data();
    }

    private byte[] parseBip32Path(String path) {
        List<ChildNumber> keypath = KeyDerivation.parsePath(path);
        if(keypath.isEmpty()) {
            return new byte[1];
        }
        if(keypath.size() > 10) {
            throw new IllegalArgumentException("Path too long");
        }
        ByteBuffer buffer = ByteBuffer.allocate(1 + keypath.size() * 4);
        buffer.put((byte)keypath.size());
        keypath.stream().map(ChildNumber::i).forEach(buffer::putInt);
        return buffer.array();
    }

    private void writeHexAmountBE(long value, ByteBuffer buffer) {
        buffer.put((byte) ((value >> 56) & 0xff));
        buffer.put((byte) ((value >> 48) & 0xff));
        buffer.put((byte) ((value >> 40) & 0xff));
        buffer.put((byte) ((value >> 32) & 0xff));
        buffer.put((byte) ((value >> 24) & 0xff));
        buffer.put((byte) ((value >> 16) & 0xff));
        buffer.put((byte) ((value >> 8) & 0xff));
        buffer.put((byte) (value & 0xff));
    }
}
