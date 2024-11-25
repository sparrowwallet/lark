package com.sparrowwallet.lark;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fazecast.jSerialComm.SerialPort;
import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.lark.args.*;
import com.sparrowwallet.lark.bitbox02.BitBoxNoiseConfig;
import com.sparrowwallet.tern.http.client.HttpClientService;
import org.hid4java.HidDevice;
import org.hid4java.HidManager;
import org.hid4java.HidServices;
import org.hid4java.HidServicesSpecification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;
import org.usb4java.Device;
import org.usb4java.DeviceDescriptor;
import org.usb4java.DeviceList;
import org.usb4java.LibUsb;

import java.util.*;

/**
 * The main interface to the library.
 */
public class Lark {
    public static final String APP_NAME = "Lark";
    public static final Version APP_VERSION = new Version("0.9");

    private static final Logger log = LoggerFactory.getLogger(Lark.class);

    private static final HttpClientService httpClientService = new HttpClientService(null);
    private static final Object lock = new Object();
    private static boolean consoleOutput;

    private String passphrase;
    private BitBoxNoiseConfig bitBoxNoiseConfig;
    private final Map<OutputDescriptor, String> walletNames = new HashMap<>();
    private final Map<OutputDescriptor, byte[]> walletRegistrations = new HashMap<>();

    static {
        LibUsb.init(null);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> LibUsb.exit(null)));
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
        synchronized(lock) {
            List<HardwareClient> foundClients = new ArrayList<>();
            foundClients.addAll(enumerateHidClients(initializeMasterFingerprint));
            foundClients.addAll(enumerateSerialClients(initializeMasterFingerprint));
            foundClients.addAll(enumerateWebusbClients(initializeMasterFingerprint));
            return foundClients;
        }
    }

    private Collection<HardwareClient> enumerateHidClients(boolean initializeMasterFingerprint) {
        HidServicesSpecification hidServicesSpecification = new HidServicesSpecification();
        hidServicesSpecification.setAutoStart(false);
        HidServices hidServices = HidManager.getHidServices(hidServicesSpecification);

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
                if(foundClients.add(hardwareClient) && initializeMasterFingerprint) {
                    hardwareClient.initializeMasterFingerprint();
                }
            } catch(DeviceNotFoundException e) {
                //ignore, hid device does not match available hardware types
            } catch(DeviceException e) {
                if(hardwareClient != null) {
                    hardwareClient.setError("Could not open client or get fingerprint information: " + e.getMessage());
                } else {
                    log.error("Error initialising hardware client", e);
                }
            }
        }

        return foundClients;
    }

    private Collection<HardwareClient> enumerateSerialClients(boolean initializeMasterFingerprint) {
        Set<HardwareClient> foundClients = new LinkedHashSet<>();

        SerialPort[] serialPorts = SerialPort.getCommPorts();
        for(SerialPort serialPort : serialPorts) {
            HardwareClient hardwareClient = null;
            try {
                hardwareClient = HardwareType.fromSerialPort(serialPort);
                hardwareClient.setWalletNames(walletNames);
                if(foundClients.add(hardwareClient) && initializeMasterFingerprint) {
                    hardwareClient.initializeMasterFingerprint();
                }
            } catch(DeviceNotFoundException e) {
                //ignore, serial device does not match available hardware types
            } catch(DeviceException e) {
                if(hardwareClient != null) {
                    hardwareClient.setError("Could not open client or get fingerprint information: " + e.getMessage());
                } else {
                    log.error("Error initialising hardware client", e);
                }
            }
        }

        return foundClients;
    }

    private Collection<HardwareClient> enumerateWebusbClients(boolean initializeMasterFingerprint) {
        Set<HardwareClient> foundClients = new LinkedHashSet<>();

        DeviceList webUsbDevices = new DeviceList();
        int result = LibUsb.getDeviceList(null, webUsbDevices);
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
                    if(hardwareClient instanceof TrezorClient trezorClient && passphrase != null) {
                        trezorClient.setPassphrase(passphrase);
                    }
                    if(foundClients.add(hardwareClient) && initializeMasterFingerprint) {
                        hardwareClient.initializeMasterFingerprint();
                    }
                } catch(DeviceNotFoundException e) {
                    //ignore, serial device does not match available hardware types
                } catch(DeviceException e) {
                    if(hardwareClient != null) {
                        hardwareClient.setError("Could not open client or get fingerprint information: " + e.getMessage());
                    } else {
                        log.error("Error initialising hardware client", e);
                    }
                }
            }
        } finally {
            LibUsb.freeDeviceList(webUsbDevices, true);
        }

        return foundClients;
    }

    private HardwareClient getHardwareClient(String deviceType) throws DeviceNotFoundException {
        List<HardwareClient> clients = enumerate(false);
        for(HardwareClient client : clients) {
            if(client.getType().equals(deviceType)) {
                return client;
            }
        }

        throw new DeviceNotFoundException("Could not find hardware client with type " + deviceType);
    }

    private HardwareClient getHardwareClient(String deviceType, String devicePath) throws DeviceNotFoundException {
        List<HardwareClient> clients = enumerate(false);
        for(HardwareClient client : clients) {
            if(client.getType().equals(deviceType) && client.getPath().equals(devicePath)) {
                return client;
            }
        }

        throw new DeviceNotFoundException("Could not find hardware client with type " + deviceType + " at path " + devicePath);
    }

    private HardwareClient getHardwareClient(byte[] fingerprint) throws DeviceNotFoundException {
        List<HardwareClient> clients = enumerate(true);
        for(HardwareClient client : clients) {
            if(client.fingerprint().equals(Utils.bytesToHex(fingerprint))) {
                return client;
            }
        }

        throw new DeviceNotFoundException("Could not find hardware client with fingerprint " + Utils.bytesToHex(fingerprint));
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType);
            return hardwareClient.getPubKeyAtPath(path);
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType, devicePath);
            return hardwareClient.getPubKeyAtPath(path);
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(fingerprint);
            return hardwareClient.getPubKeyAtPath(path);
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType);
            return hardwareClient.signTransaction(psbt);
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType, devicePath);
            return hardwareClient.signTransaction(psbt);
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(fingerprint);
            return hardwareClient.signTransaction(psbt);
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType);
            return hardwareClient.signMessage(message, path);
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType, devicePath);
            return hardwareClient.signMessage(message, path);
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(fingerprint);
            return hardwareClient.signMessage(message, path);
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType);
            return hardwareClient.displaySinglesigAddress(path, scriptType);
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType, devicePath);
            return hardwareClient.displaySinglesigAddress(path, scriptType);
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(fingerprint);
            return hardwareClient.displaySinglesigAddress(path, scriptType);
        }
    }

    private String displayMultisigAddress(String deviceType, OutputDescriptor outputDescriptor) throws DeviceException {
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType);
            return hardwareClient.displayMultisigAddress(outputDescriptor);
        }
    }

    private String displayMultisigAddress(String deviceType, String devicePath, OutputDescriptor outputDescriptor) throws DeviceException {
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType, devicePath);
            return hardwareClient.displayMultisigAddress(outputDescriptor);
        }
    }

    private String displayMultisigAddress(byte[] fingerprint, OutputDescriptor outputDescriptor) throws DeviceException {
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(fingerprint);
            return hardwareClient.displayMultisigAddress(outputDescriptor);
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType);
            return hardwareClient.promptPin();
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType, devicePath);
            return hardwareClient.promptPin();
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(fingerprint);
            return hardwareClient.promptPin();
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType);
            return hardwareClient.sendPin(pin);
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType, devicePath);
            return hardwareClient.sendPin(pin);
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(fingerprint);
            return hardwareClient.sendPin(pin);
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType);
            return hardwareClient.togglePassphrase();
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(deviceType, devicePath);
            return hardwareClient.togglePassphrase();
        }
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
        synchronized(lock) {
            HardwareClient hardwareClient = getHardwareClient(fingerprint);
            return hardwareClient.togglePassphrase();
        }
    }

    public static HttpClientService getHttpClientService() {
        return httpClientService;
    }

    public static boolean isConsoleOutput() {
        return consoleOutput;
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

    public static void main(String[] argv) throws Exception {
        consoleOutput = true;
        List<Command> commands = List.of(
                new EnumerateCommand(),
                new PromptPinCommand(),
                new SendPinCommand(),
                new GetXpubCommand(),
                new GetMasterXpubCommand(),
                new SignTxCommand(),
                new SignMessageCommand(),
                new DisplayAddressCommand(),
                new TogglePassphraseCommand());

        Args args = new Args();
        JCommander.Builder jCommanderBuilder = JCommander.newBuilder()
                .addObject(args)
                .programName(APP_NAME.toLowerCase(Locale.ROOT));
        for(Command command : commands) {
            jCommanderBuilder.addCommand(command.getName(), command);
        }
        JCommander jCommander = jCommanderBuilder.build();

        try {
            jCommander.parse(argv);
        } catch(ParameterException e) {
            showErrorAndExit(e.getMessage());
        }

        if(args.help) {
            jCommander.usage();
            System.exit(0);
        }

        if(args.version) {
            System.out.println(APP_NAME + " " + APP_VERSION);
            System.exit(0);
        }

        if(args.level != null) {
            Drongo.setRootLogLevel(args.level);
        } else if(args.debug) {
            Drongo.setRootLogLevel(Level.DEBUG);
        }

        if(args.network != null) {
            Network.set(args.network);
        } else if(args.chain != null) {
            Network.set(args.chain.getNetwork());
        }

        Lark lark = new Lark();
        if(args.passphrase != null) {
            lark.setPassphrase(args.passphrase);
        }

        if(args.walletRegistration != null) {
            if(args.walletDescriptor == null || args.walletName == null) {
                System.err.println("If `--wallet-registration` is provided, `--wallet-descriptor` and `--wallet-name` must also be provided");
                System.exit(1);
            }
            OutputDescriptor walletDescriptor = getWalletDescriptor(args);
            byte[] walletRegistration = getWalletRegistration(args);
            lark.addWalletRegistration(walletDescriptor, args.walletName, walletRegistration);
        } else if(args.walletName != null) {
            if(args.walletDescriptor == null) {
                System.err.println("If `--wallet-name` is provided, `--wallet-descriptor` must also be provided");
                System.exit(1);
            }
            OutputDescriptor walletDescriptor = getWalletDescriptor(args);
            lark.addWalletName(walletDescriptor, args.walletName);
        }

        try {
            for(Command command : commands) {
                if(command.getName().equals(jCommander.getParsedCommand())) {
                    command.run(jCommander, lark, args);
                }
            }
        } catch(DeviceException e) {
            showErrorAndExit(e.getMessage());
        }
    }

    private static OutputDescriptor getWalletDescriptor(Args args) {
        try {
            return OutputDescriptor.getOutputDescriptor(args.walletDescriptor);
        } catch(Exception e) {
            System.err.println("Invalid wallet descriptor: " + e.getMessage());
            System.exit(1);
            return null;
        }
    }

    private static byte[] getWalletRegistration(Args args) {
        try {
            return Utils.hexToBytes(args.walletRegistration);
        } catch(Exception e) {
            System.err.println("Invalid wallet registration: " + e.getMessage());
            System.exit(1);
            return null;
        }
    }

    public static void showSuccess(boolean success) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            System.out.println(objectMapper.writeValueAsString(new Lark.Success(success)));
        } catch(JsonProcessingException e) {
            log.error("Failed to serialize error", e);
        }
    }

    public static void showValue(Object value) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            System.out.println(objectMapper.writeValueAsString(value));
        } catch(JsonProcessingException e) {
            log.error("Failed to serialize error", e);
        }
    }

    public static void showErrorAndExit(String errorMessage) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            System.err.println(objectMapper.writeValueAsString(new Error(errorMessage)));
            System.exit(1);
        } catch(JsonProcessingException e) {
            log.error("Failed to serialize error", e);
        }
    }

    private record Success(boolean success) {
    }

    private record Error(String error) {
    }
}