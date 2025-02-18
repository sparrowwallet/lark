package com.sparrowwallet.lark;

import com.fazecast.jSerialComm.SerialPort;
import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.lark.bitbox02.BitBoxNoiseConfig;
import com.sparrowwallet.tern.http.client.HttpClientService;
import org.hid4java.HidDevice;
import org.hid4java.HidManager;
import org.hid4java.HidServices;
import org.hid4java.HidServicesSpecification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.usb4java.*;

import java.util.*;

/**
 * The main interface to the library.
 */
public class Lark {
    private static final Logger log = LoggerFactory.getLogger(Lark.class);

    private static final Object lock = new Object();
    private static boolean consoleOutput;

    private final HttpClientService httpClientService;
    private String passphrase;
    private BitBoxNoiseConfig bitBoxNoiseConfig;
    private final Map<OutputDescriptor, String> walletNames = new HashMap<>();
    private final Map<OutputDescriptor, byte[]> walletRegistrations = new HashMap<>();

    public Lark() {
        this(new HttpClientService());
    }

    public Lark(HttpClientService httpClientService) {
        this.httpClientService = httpClientService;
    }

    /**
     * Retrieves a list of all connected devices with the given hardware type.
     * The master fingerprints will be initialized.
     *
     * @param hardwareType the type of the devices to filter on
     * @return a list of all connected devices with the given type
     */
    public List<HardwareClient> enumerate(HardwareType hardwareType) {
        return enumerate().stream().filter(device -> device.getHardwareType() == hardwareType).toList();
    }

    /**
     * Retrieves a list of all connected devices with the given model.
     * The master fingerprints will be initialized.
     *
     * @param walletModel the model of the devices to filter on
     * @return a list of all connected devices with the given model
     */
    public List<HardwareClient> enumerate(WalletModel walletModel) {
        return enumerate().stream().filter(device -> device.getModel() == walletModel).toList();
    }

    /**
     * Retrieves a list of all connected devices.
     * The master fingerprints will be initialized.
     *
     * @return a list of all connected devices
     */
    public List<HardwareClient> enumerate() {
        return enumerate(true);
    }

    private List<HardwareClient> enumerate(boolean initializeMasterFingerprint) {
        try {
            EnumerateOperation enumerateOperation = initializeMasterFingerprint ? new InitializeFingerprintOperation() : new EnumerateOperation();
            enumerate(enumerateOperation);
            return enumerateOperation.getHardwareClients();
        } catch(DeviceException e) {
            log.error("Error enumerating devices", e);
        }

        return Collections.emptyList();
    }

    private void enumerate(ClientOperation clientOperation) throws DeviceException {
        synchronized(lock) {
            enumerateHidClients(clientOperation);
            enumerateSerialClients(clientOperation);
            enumerateWebusbClients(clientOperation);
            if(!clientOperation.success()) {
                throw new DeviceNotFoundException("Could not find device with specified type or fingerprint");
            }
        }
    }

    private void enumerateHidClients(ClientOperation clientOperation) throws DeviceException {
        if(!clientOperation.requires(Interface.HID)) {
            return;
        }

        HidServicesSpecification hidServicesSpecification = new HidServicesSpecification();
        hidServicesSpecification.setAutoStart(false);
        hidServicesSpecification.setAutoShutdown(false);
        HidServices hidServices = HidManager.getHidServices(hidServicesSpecification);

        try {
            Set<HardwareClient> foundClients = new LinkedHashSet<>();
            for(HidDevice hidDevice : hidServices.getAttachedHidDevices()) {
                HardwareClient hardwareClient = null;
                try {
                    hardwareClient = HardwareType.fromHidDevice(hidDevice);
                    hardwareClient.setWalletNames(walletNames);
                    if(hardwareClient instanceof BitBox02Client bitBox02Client && bitBoxNoiseConfig != null) {
                        bitBox02Client.setNoiseConfig(bitBoxNoiseConfig);
                    }
                    if(hardwareClient instanceof LedgerClient ledgerClient) {
                        ledgerClient.setWalletRegistrations(walletRegistrations);
                    }
                    if(foundClients.add(hardwareClient) && clientOperation != null && clientOperation.matches(hardwareClient)) {
                        clientOperation.apply(hardwareClient);
                    }
                } catch(DeviceNotFoundException e) {
                    //ignore, hid device does not match available hardware types
                } catch(DeviceException e) {
                    if(hardwareClient != null && clientOperation instanceof InitializeFingerprintOperation) {
                        hardwareClient.setError("Could not open device or get fingerprint: " + e.getMessage() +
                                (OsType.getCurrent() == OsType.UNIX ? ". Are udev rules installed?" : ""));
                    } else {
                        throw e;
                    }
                }
            }
        } finally {
            hidServices.shutdown();
        }
    }

    private void enumerateSerialClients(ClientOperation clientOperation) throws DeviceException {
        if(!clientOperation.requires(Interface.SERIAL)) {
            return;
        }

        Set<HardwareClient> foundClients = new LinkedHashSet<>();

        SerialPort[] serialPorts = SerialPort.getCommPorts();
        for(SerialPort serialPort : serialPorts) {
            HardwareClient hardwareClient = null;
            try {
                hardwareClient = HardwareType.fromSerialPort(serialPort, httpClientService);
                hardwareClient.setWalletNames(walletNames);
                if(foundClients.add(hardwareClient) && clientOperation != null && clientOperation.matches(hardwareClient)) {
                    clientOperation.apply(hardwareClient);
                }
            } catch(DeviceNotFoundException e) {
                //ignore, serial device does not match available hardware types
            } catch(DeviceException e) {
                if(hardwareClient != null && clientOperation instanceof InitializeFingerprintOperation) {
                    hardwareClient.setError("Could not open device or get fingerprint: " + e.getMessage() +
                            (OsType.getCurrent() == OsType.UNIX ? ". Are udev rules installed?" : ""));
                } else {
                    throw e;
                }
            }
        }
    }

    private void enumerateWebusbClients(ClientOperation clientOperation) throws DeviceException {
        if(!clientOperation.requires(Interface.WEBUSB)) {
            return;
        }

        Context context = new Context();
        LibUsb.init(context);

        Set<HardwareClient> foundClients = new LinkedHashSet<>();

        DeviceList webUsbDevices = new DeviceList();
        int result = LibUsb.getDeviceList(context, webUsbDevices);
        if(result < 0) {
            log.error("Unable to list webusb devices, operation returned " + result);
        }

        try {
            for(Device device : webUsbDevices) {
                HardwareClient hardwareClient = null;
                try {
                    DeviceDescriptor descriptor = new DeviceDescriptor();
                    result = LibUsb.getDeviceDescriptor(device, descriptor);
                    if(result != LibUsb.SUCCESS) {
                        continue;
                    }
                    descriptor.iProduct();
                    hardwareClient = HardwareType.fromWebusbDevice(device, descriptor);
                    hardwareClient.setWalletNames(walletNames);
                    if(hardwareClient instanceof TrezorClient trezorClient) {
                        trezorClient.setPassphrase(passphrase);
                    }
                    if(foundClients.add(hardwareClient) && clientOperation != null && clientOperation.matches(hardwareClient)) {
                        clientOperation.apply(hardwareClient);
                    }
                } catch(DeviceNotFoundException e) {
                    //ignore, serial device does not match available hardware types
                } catch(DeviceException e) {
                    if(hardwareClient != null && clientOperation instanceof InitializeFingerprintOperation) {
                        hardwareClient.setError("Could not open device or get fingerprint: " + e.getMessage() +
                                (OsType.getCurrent() == OsType.UNIX ? ". Are udev rules installed?" : "") +
                                (OsType.getCurrent() == OsType.WINDOWS ? ". See [https://sparrowwallet.com/docs/faq.html#i-cant-connect-to-my-trezor]" : ""));
                    } else {
                        throw e;
                    }
                }
            }
        } finally {
            LibUsb.freeDeviceList(webUsbDevices, true);
            if(context.getPointer() != 0) {
                LibUsb.exit(context);
            }
        }
    }

    /**
     * Retrieves the xpub at the given path.
     *
     * @param deviceType the device type
     * @param path       the derivation path
     * @return the xpub at the given derivation path
     * @throws DeviceException if an error occurs
     */
    public ExtendedKey getPubKeyAtPath(String deviceType, String path) throws DeviceException {
        GetXpubOperation getXpubOperation = new GetXpubOperation(deviceType, path);
        enumerate(getXpubOperation);
        return getXpubOperation.getXpub();
    }

    /**
     * Retrieves the xpub at the given path.
     *
     * @param deviceType the device type
     * @param devicePath this device path
     * @param path       the derivation path
     * @return the xpub at the given derivation path
     * @throws DeviceException if an error occurs
     */
    public ExtendedKey getPubKeyAtPath(String deviceType, String devicePath, String path) throws DeviceException {
        GetXpubOperation getXpubOperation = new GetXpubOperation(deviceType, devicePath, path);
        enumerate(getXpubOperation);
        return getXpubOperation.getXpub();
    }

    /**
     * Retrieves the xpub at the given path.
     *
     * @param fingerprint the device master fingerprint
     * @param path        the derivation path
     * @return the xpub at the given derivation path
     * @throws DeviceException if an error occurs
     */
    public ExtendedKey getPubKeyAtPath(byte[] fingerprint, String path) throws DeviceException {
        GetXpubOperation getXpubOperation = new GetXpubOperation(fingerprint, path);
        enumerate(getXpubOperation);
        return getXpubOperation.getXpub();
    }

    /**
     * Signs the provided PSBT.
     *
     * @param deviceType the device type
     * @param psbt       the PSBT to be signed
     * @return the signed PSBT
     * @throws DeviceException if an error occurs
     */
    public PSBT signTransaction(String deviceType, PSBT psbt) throws DeviceException {
        SignPsbtOperation signPsbtOperation = new SignPsbtOperation(deviceType, psbt);
        enumerate(signPsbtOperation);
        return signPsbtOperation.getPsbt();
    }

    /**
     * Signs the provided PSBT.
     *
     * @param deviceType the device type
     * @param devicePath this device path
     * @param psbt       the PSBT to be signed
     * @return the signed PSBT
     * @throws DeviceException if an error occurs
     */
    public PSBT signTransaction(String deviceType, String devicePath, PSBT psbt) throws DeviceException {
        SignPsbtOperation signPsbtOperation = new SignPsbtOperation(deviceType, devicePath, psbt);
        enumerate(signPsbtOperation);
        return signPsbtOperation.getPsbt();
    }

    /**
     * Signs the provided PSBT.
     *
     * @param fingerprint the device master fingerprint
     * @param psbt        the PSBT to be signed
     * @return the signed PSBT
     * @throws DeviceException if an error occurs
     */
    public PSBT signTransaction(byte[] fingerprint, PSBT psbt) throws DeviceException {
        SignPsbtOperation signPsbtOperation = new SignPsbtOperation(fingerprint, psbt);
        enumerate(signPsbtOperation);
        return signPsbtOperation.getPsbt();
    }

    /**
     * Requests the device to sign the provided message using the address at the given path.
     * Note that only legacy signing is supported.
     *
     * @param deviceType the device type
     * @param message    the message to be signed
     * @param path       the path to the address signing the message
     * @return the signature
     * @throws DeviceException if an error occurs
     */
    public String signMessage(String deviceType, String message, String path) throws DeviceException {
        SignMessageOperation signMessageOperation = new SignMessageOperation(deviceType, message, path);
        enumerate(signMessageOperation);
        return signMessageOperation.getSignature();
    }

    /**
     * Requests the device to sign the provided message using the address at the given path.
     * Note that only legacy signing is supported.
     *
     * @param deviceType the device type
     * @param devicePath this device path
     * @param message    the message to be signed
     * @param path       the path to the address signing the message
     * @return the signature
     * @throws DeviceException if an error occurs
     */
    public String signMessage(String deviceType, String devicePath, String message, String path) throws DeviceException {
        SignMessageOperation signMessageOperation = new SignMessageOperation(deviceType, devicePath, message, path);
        enumerate(signMessageOperation);
        return signMessageOperation.getSignature();
    }

    /**
     * Requests the device to sign the provided message using the address at the given path.
     * Note that only legacy signing is supported.
     *
     * @param fingerprint the device master fingerprint
     * @param message     the message to be signed
     * @param path        the path to the address signing the message
     * @return the signature
     * @throws DeviceException if an error occurs
     */
    public String signMessage(byte[] fingerprint, String message, String path) throws DeviceException {
        SignMessageOperation signMessageOperation = new SignMessageOperation(fingerprint, message, path);
        enumerate(signMessageOperation);
        return signMessageOperation.getSignature();
    }

    /**
     * Requests the device to display the address for the provided output descriptor.
     *
     * @param deviceType       the device type
     * @param outputDescriptor the output descriptor providing the full path to the address
     * @return the address
     * @throws DeviceException if an error occurs
     */
    public String displayAddress(String deviceType, OutputDescriptor outputDescriptor) throws DeviceException {
        if(outputDescriptor.isMultisig()) {
            return displayMultisigAddress(deviceType, outputDescriptor);
        } else {
            ExtendedKey xpub = outputDescriptor.getSingletonExtendedPublicKey();
            KeyDerivation addressDerivation = outputDescriptor.getKeyDerivation(xpub);
            List<ChildNumber> childDerivation = outputDescriptor.getChildDerivation(xpub);
            if(childDerivation != null) {
                addressDerivation = addressDerivation.extend(childDerivation.subList(1, childDerivation.size()));
            }

            String path = addressDerivation.getDerivationPath();
            ScriptType scriptType = outputDescriptor.getScriptType();
            return displaySinglesigAddress(deviceType, path, scriptType);
        }
    }

    /**
     * Requests the device to display the address for the provided output descriptor.
     *
     * @param deviceType       the device type
     * @param devicePath       this device path
     * @param outputDescriptor the output descriptor providing the full path to the address
     * @return the address
     * @throws DeviceException if an error occurs
     */
    public String displayAddress(String deviceType, String devicePath, OutputDescriptor outputDescriptor) throws DeviceException {
        if(outputDescriptor.isMultisig()) {
            return displayMultisigAddress(deviceType, devicePath, outputDescriptor);
        } else {
            ExtendedKey xpub = outputDescriptor.getSingletonExtendedPublicKey();
            KeyDerivation addressDerivation = outputDescriptor.getKeyDerivation(xpub);
            List<ChildNumber> childDerivation = outputDescriptor.getChildDerivation(xpub);
            if(childDerivation != null) {
                addressDerivation = addressDerivation.extend(childDerivation.subList(1, childDerivation.size()));
            }

            String path = addressDerivation.getDerivationPath();
            ScriptType scriptType = outputDescriptor.getScriptType();
            return displaySinglesigAddress(deviceType, devicePath, path, scriptType);
        }
    }

    /**
     * Requests the device to display the address for the provided output descriptor.
     *
     * @param fingerprint      the device master fingerprint
     * @param outputDescriptor the output descriptor providing the full path to the address
     * @return the address
     * @throws DeviceException if an error occurs
     */
    public String displayAddress(byte[] fingerprint, OutputDescriptor outputDescriptor) throws DeviceException {
        if(outputDescriptor.isMultisig()) {
            return displayMultisigAddress(fingerprint, outputDescriptor);
        } else {
            ExtendedKey xpub = outputDescriptor.getSingletonExtendedPublicKey();
            KeyDerivation addressDerivation = outputDescriptor.getKeyDerivation(xpub);
            List<ChildNumber> childDerivation = outputDescriptor.getChildDerivation(xpub);
            if(childDerivation != null) {
                addressDerivation = addressDerivation.extend(childDerivation.subList(1, childDerivation.size()));
            }

            String path = addressDerivation.getDerivationPath();
            ScriptType scriptType = outputDescriptor.getScriptType();
            return displaySinglesigAddress(fingerprint, path, scriptType);
        }
    }

    /**
     * Requests the device to display the address for the provided path and script type.
     *
     * @param deviceType the device type
     * @param path       the full derivation path to the address
     * @param scriptType the script type of the address
     * @return the address
     * @throws DeviceException if an error occurs
     */
    public String displaySinglesigAddress(String deviceType, String path, ScriptType scriptType) throws DeviceException {
        DisplayAddressOperation displayAddressOperation = new DisplayAddressOperation(deviceType, path, scriptType);
        enumerate(displayAddressOperation);
        return displayAddressOperation.getAddress();
    }

    /**
     * Requests the device to display the address for the provided path and script type.
     *
     * @param deviceType the device type
     * @param devicePath the device path
     * @param path       the full derivation path to the address
     * @param scriptType the script type of the address
     * @return the address
     * @throws DeviceException if an error occurs
     */
    public String displaySinglesigAddress(String deviceType, String devicePath, String path, ScriptType scriptType) throws DeviceException {
        DisplayAddressOperation displayAddressOperation = new DisplayAddressOperation(deviceType, devicePath, path, scriptType);
        enumerate(displayAddressOperation);
        return displayAddressOperation.getAddress();
    }

    /**
     * Requests the device to display the address for the provided path and script type.
     *
     * @param fingerprint the device master fingerprint
     * @param path        the full derivation path to the address
     * @param scriptType  the script type of the address
     * @return the address
     * @throws DeviceException if an error occurs
     */
    public String displaySinglesigAddress(byte[] fingerprint, String path, ScriptType scriptType) throws DeviceException {
        DisplayAddressOperation displayAddressOperation = new DisplayAddressOperation(fingerprint, path, scriptType);
        enumerate(displayAddressOperation);
        return displayAddressOperation.getAddress();
    }

    private String displayMultisigAddress(String deviceType, OutputDescriptor outputDescriptor) throws DeviceException {
        DisplayAddressOperation displayAddressOperation = new DisplayAddressOperation(deviceType, outputDescriptor);
        enumerate(displayAddressOperation);
        return displayAddressOperation.getAddress();
    }

    private String displayMultisigAddress(String deviceType, String devicePath, OutputDescriptor outputDescriptor) throws DeviceException {
        DisplayAddressOperation displayAddressOperation = new DisplayAddressOperation(deviceType, devicePath, outputDescriptor);
        enumerate(displayAddressOperation);
        return displayAddressOperation.getAddress();
    }

    private String displayMultisigAddress(byte[] fingerprint, OutputDescriptor outputDescriptor) throws DeviceException {
        DisplayAddressOperation displayAddressOperation = new DisplayAddressOperation(fingerprint, outputDescriptor);
        enumerate(displayAddressOperation);
        return displayAddressOperation.getAddress();
    }

    /**
     * Asks the device to prompt for a PIN.
     * Only applicable for Trezor One and KeepKey.
     *
     * @param deviceType the device type
     * @return whether the operation was successful
     * @throws DeviceException if an error occurs
     */
    public synchronized boolean promptPin(String deviceType) throws DeviceException {
        PromptPinOperation promptPinOperation = new PromptPinOperation(deviceType);
        enumerate(promptPinOperation);
        return promptPinOperation.getResult();
    }

    /**
     * Asks the device to prompt for a PIN.
     * Only applicable for Trezor One and KeepKey.
     *
     * @param deviceType the device type
     * @param devicePath this device path
     * @return whether the operation was successful
     * @throws DeviceException if an error occurs
     */
    public synchronized boolean promptPin(String deviceType, String devicePath) throws DeviceException {
        PromptPinOperation promptPinOperation = new PromptPinOperation(deviceType, devicePath);
        enumerate(promptPinOperation);
        return promptPinOperation.getResult();
    }

    /**
     * Asks the device to prompt for a PIN.
     * Only applicable for Trezor One and KeepKey.
     *
     * @param fingerprint the device master fingerprint
     * @return whether the operation was successful
     * @throws DeviceException if an error occurs
     */
    public synchronized boolean promptPin(byte[] fingerprint) throws DeviceException {
        PromptPinOperation promptPinOperation = new PromptPinOperation(fingerprint);
        enumerate(promptPinOperation);
        return promptPinOperation.getResult();
    }

    /**
     * Sends a PIN to the device.
     * Only applicable for Trezor One and KeepKey.
     *
     * @param deviceType the device type
     * @param pin        the device PIN
     * @return whether the operation was successful
     * @throws DeviceException if an error occurs
     */
    public synchronized boolean sendPin(String deviceType, String pin) throws DeviceException {
        SendPinOperation sendPinOperation = new SendPinOperation(deviceType, pin);
        enumerate(sendPinOperation);
        return sendPinOperation.getResult();
    }

    /**
     * Sends a PIN to the device.
     * Only applicable for Trezor One and KeepKey.
     *
     * @param deviceType the device type
     * @param devicePath this device path
     * @param pin        the device PIN
     * @return whether the operation was successful
     * @throws DeviceException if an error occurs
     */
    public synchronized boolean sendPin(String deviceType, String devicePath, String pin) throws DeviceException {
        SendPinOperation sendPinOperation = new SendPinOperation(deviceType, devicePath, pin);
        enumerate(sendPinOperation);
        return sendPinOperation.getResult();
    }

    /**
     * Sends a PIN to the device.
     * Only applicable for Trezor One and KeepKey.
     *
     * @param fingerprint the device master fingerprint
     * @param pin         the device PIN
     * @return whether the operation was successful
     * @throws DeviceException if an error occurs
     */
    public synchronized boolean sendPin(byte[] fingerprint, String pin) throws DeviceException {
        SendPinOperation sendPinOperation = new SendPinOperation(fingerprint, pin);
        enumerate(sendPinOperation);
        return sendPinOperation.getResult();
    }

    /**
     * Toggles whether a BIP39 passphrase is requested by the device.
     * Not applicable to all devices.
     *
     * @param deviceType the device type
     * @return whether the operation was successful
     * @throws DeviceException if an error occurs
     */
    public synchronized boolean togglePassphrase(String deviceType) throws DeviceException {
        TogglePassphraseOperation togglePassphraseOperation = new TogglePassphraseOperation(deviceType);
        enumerate(togglePassphraseOperation);
        return togglePassphraseOperation.getResult();
    }

    /**
     * Toggles whether a BIP39 passphrase is requested by the device.
     * Not applicable to all devices.
     *
     * @param deviceType the device type
     * @param devicePath this device path
     * @return whether the operation was successful
     * @throws DeviceException if an error occurs
     */
    public synchronized boolean togglePassphrase(String deviceType, String devicePath) throws DeviceException {
        TogglePassphraseOperation togglePassphraseOperation = new TogglePassphraseOperation(deviceType, devicePath);
        enumerate(togglePassphraseOperation);
        return togglePassphraseOperation.getResult();
    }

    /**
     * Toggles whether a BIP39 passphrase is requested by the device.
     * Not applicable to all devices.
     *
     * @param fingerprint the device master fingerprint
     * @return whether the operation was successful
     * @throws DeviceException if an error occurs
     */
    public synchronized boolean togglePassphrase(byte[] fingerprint) throws DeviceException {
        TogglePassphraseOperation togglePassphraseOperation = new TogglePassphraseOperation(fingerprint);
        enumerate(togglePassphraseOperation);
        return togglePassphraseOperation.getResult();
    }

    public static boolean isConsoleOutput() {
        return consoleOutput;
    }

    public static void setConsoleOutput(boolean consoleOutput) {
        Lark.consoleOutput = consoleOutput;
    }

    /**
     * Sets the noise configuration for the BitBox02 client.
     * This includes methods to complete pairing a device to this client if necessary.
     *
     * @param bitBoxNoiseConfig the noise configuration
     */
    public void setBitBoxNoiseConfig(BitBoxNoiseConfig bitBoxNoiseConfig) {
        this.bitBoxNoiseConfig = bitBoxNoiseConfig;
    }

    /**
     * Sets the passphrase to use with the device, if one can be set from this client.
     *
     * @param passphrase the BIP39 passphrase
     */
    public void setPassphrase(String passphrase) {
        this.passphrase = passphrase;
    }

    /**
     * Gets any names that have been set.
     *
     * @return a map of output descriptors to wallet names
     */
    public Map<OutputDescriptor, String> getWalletNames() {
        return Collections.unmodifiableMap(walletNames);
    }

    /**
     * Provides a name for a wallet if one is registered on a device
     *
     * @param outputDescriptor output descriptor identifying the wallet
     * @param name             the wallet name
     */
    public void addWalletName(OutputDescriptor outputDescriptor, String name) {
        walletNames.put(outputDescriptor.copy(false), name);
    }

    /**
     * Gets the wallet name for a given output descriptor, if set.
     *
     * @param outputDescriptor output descriptor identifying the wallet
     * @return the wallet name
     */
    public String getWalletName(OutputDescriptor outputDescriptor) {
        return walletNames.get(outputDescriptor.copy(false));
    }

    /**
     * Gets any registrations that have been set, either by this API or a device.
     *
     * @return a map of output descriptors to byte arrays representing an internal ids used by a device
     */
    public Map<OutputDescriptor, byte[]> getWalletRegistrations() {
        return Collections.unmodifiableMap(walletRegistrations);
    }

    /**
     * Provides details of an existing wallet registered on a device.
     * This is used for Ledger devices. Note that the name provided MUST be the same as that provided when the wallet was originally registered!
     *
     * @param outputDescriptor output descriptor identifying the wallet
     * @param name             the wallet name
     * @param registration     a byte array representing an internal id used by a device
     */
    public void addWalletRegistration(OutputDescriptor outputDescriptor, String name, byte[] registration) {
        addWalletName(outputDescriptor, name);
        walletRegistrations.put(outputDescriptor.copy(false), registration);
    }

    /**
     * Gets a wallet registration that has been set, either by this API or a device.
     *
     * @param outputDescriptor output descriptor identifying the wallet
     * @return a byte array representing an internal id used by a device
     */
    public byte[] getWalletRegistration(OutputDescriptor outputDescriptor) {
        return walletRegistrations.get(outputDescriptor.copy(false));
    }
}