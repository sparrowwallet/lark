package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.OutputDescriptor;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.wallet.WalletModel;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

public abstract class HardwareClient {
    protected String error;
    protected Map<OutputDescriptor, String> walletNames = new HashMap<>();

    abstract void initializeMasterFingerprint() throws DeviceException;
    abstract ExtendedKey getPubKeyAtPath(String path) throws DeviceException;
    abstract PSBT signTransaction(PSBT psbt) throws DeviceException;
    abstract String signMessage(String message, String path) throws DeviceException;
    abstract String displaySinglesigAddress(String path, ScriptType scriptType) throws DeviceException;
    abstract String displayMultisigAddress(OutputDescriptor outputDescriptor) throws DeviceException;

    public String getType() {
        return getHardwareType().getName();
    }

    public abstract String getPath();
    public abstract HardwareType getHardwareType();
    public abstract WalletModel getModel();
    public abstract Boolean needsPinSent();
    public abstract Boolean needsPassphraseSent();
    public abstract String fingerprint();
    public abstract boolean card();
    public abstract String[][] warnings();

    public String error() {
        return error;
    }

    void setError(String error) {
        this.error = error;
    }

    public boolean promptPin() throws DeviceException {
        throw new DeviceException("The " + getHardwareType().getDisplayName() + " does not need a PIN sent from the host");
    }

    public boolean sendPin(String pin) throws DeviceException {
        throw new DeviceException("The " + getHardwareType().getDisplayName() + " does not need a PIN sent from the host");
    }

    public boolean togglePassphrase() throws DeviceException {
        throw new DeviceException("The " + getHardwareType().getDisplayName() + " does not support toggling passphrase from the host");
    }

    public String getLabel() {
        return null;
    }

    public String getProductModel() {
        return getType();
    }

    @Override
    public String toString() {
        return "{type=\"" + getType() +
                "\", model=\"" + getModel() +
                "\", path=\"" + getPath() +
                "\", fingerprint=\"" + fingerprint() +
                "\", needsPinSent=\"" + needsPinSent() +
                "\", needsPassphraseSent=\"" + needsPassphraseSent() +
                "\", warnings=\"" + Arrays.deepToString(warnings()) +
                "\", error=\"" + error() + "\"}";
    }

    public void setWalletNames(Map<OutputDescriptor, String> walletNames) {
        this.walletNames = walletNames;
    }

    protected String getWalletNameOrDefault(OutputDescriptor outputDescriptor) {
        return getWalletNameOrDefault(outputDescriptor, null);
    }

    protected String getWalletNameOrDefault(OutputDescriptor outputDescriptor, PSBT psbt) {
        String name = getWalletName(outputDescriptor);
        if(name == null) {
            if(psbt != null) {
                name = getWalletName(psbt);
            }

            if(name == null) {
                if(outputDescriptor.isMultisig()) {
                    name = outputDescriptor.getMultisigThreshold() + " of " + outputDescriptor.getExtendedPublicKeys().size() + " Multisig";
                } else {
                    name = "Singlesig";
                }
            }
        }

        return name;
    }

    private String getWalletName(PSBT psbt) {
        Optional<Script> optSigningScript = psbt.getPsbtInputs().stream().filter(psbtInput -> psbtInput.getUtxo() != null).map(PSBTInput::getSigningScript).findFirst();
        if(optSigningScript.isPresent()) {
            if(ScriptType.MULTISIG.isScriptType(optSigningScript.get())) {
                int threshold = ScriptType.MULTISIG.getThreshold(optSigningScript.get());
                int keys = ScriptType.MULTISIG.getPublicKeysFromScript(optSigningScript.get()).length;
                return threshold + " of " + keys + " Multisig";
            } else {
                return "Singlesig";
            }
        }

        return null;
    }

    protected String getWalletName(OutputDescriptor walletDescriptor) {
        return walletNames.get(walletDescriptor.copy(false));
    }

    /**
     * Serialize a 256-bit integer with Bitcoin's 256-bit integer serialization.
     *
     * @param u The 256-bit integer as a BigInteger
     * @return The serialized 256-bit integer as a byte array
     */
    public static byte[] serUInt256(BigInteger u) {
        ByteBuffer buffer = ByteBuffer.allocate(32);
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        // Write each 32-bit segment from the BigInteger to the buffer
        for (int i = 0; i < 8; i++) {
            int segment = u.and(BigInteger.valueOf(0xFFFFFFFFL)).intValue();
            buffer.putInt(segment);
            u = u.shiftRight(32);
        }

        return buffer.array();
    }

    public static Optional<ScriptType> isWitness(Script inputScript) {
        return Stream.of(ScriptType.P2WPKH, ScriptType.P2WSH, ScriptType.P2TR)
                .filter(scriptType -> scriptType.isScriptType(inputScript)).findFirst();
    }
}
