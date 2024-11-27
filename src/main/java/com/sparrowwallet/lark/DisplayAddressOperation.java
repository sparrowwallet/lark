package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.OutputDescriptor;
import com.sparrowwallet.drongo.protocol.ScriptType;

public class DisplayAddressOperation extends AbstractClientOperation {
    private final OutputDescriptor outputDescriptor;
    private final String path;
    private final ScriptType scriptType;
    private String address;

    public DisplayAddressOperation(String deviceType, OutputDescriptor outputDescriptor) {
        super(deviceType);
        this.outputDescriptor = outputDescriptor;
        this.path = null;
        this.scriptType = null;
    }

    public DisplayAddressOperation(String deviceType, String devicePath, OutputDescriptor outputDescriptor) {
        super(deviceType, devicePath);
        this.outputDescriptor = outputDescriptor;
        this.path = null;
        this.scriptType = null;
    }

    public DisplayAddressOperation(byte[] fingerprint, OutputDescriptor outputDescriptor) {
        super(fingerprint);
        this.outputDescriptor = outputDescriptor;
        this.path = null;
        this.scriptType = null;
    }

    public DisplayAddressOperation(String deviceType, String path, ScriptType scriptType) {
        super(deviceType);
        this.outputDescriptor = null;
        this.path = path;
        this.scriptType = scriptType;
    }

    public DisplayAddressOperation(String deviceType, String devicePath, String path, ScriptType scriptType) {
        super(deviceType, devicePath);
        this.outputDescriptor = null;
        this.path = path;
        this.scriptType = scriptType;
    }

    public DisplayAddressOperation(byte[] fingerprint, String path, ScriptType scriptType) {
        super(fingerprint);
        this.outputDescriptor = null;
        this.path = path;
        this.scriptType = scriptType;
    }

    @Override
    public void apply(HardwareClient hardwareClient) throws DeviceException {
        if(outputDescriptor != null) {
            address = hardwareClient.displayMultisigAddress(outputDescriptor);
        } else {
            address = hardwareClient.displaySinglesigAddress(path, scriptType);
        }
    }

    public String getAddress() {
        return address;
    }
}
