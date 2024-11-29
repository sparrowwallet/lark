package com.sparrowwallet.lark;

import com.fazecast.jSerialComm.SerialPort;
import com.sparrowwallet.tern.http.client.HttpClientService;
import org.hid4java.HidDevice;
import org.usb4java.Device;
import org.usb4java.DeviceDescriptor;

public enum HardwareType {
    COLDCARD("coldcard", Interface.HID) {
        @Override
        public HardwareClient createClient(HidDevice hidDevice) throws DeviceException {
            return new ColdcardClient(hidDevice);
        }
    },
    JADE("jade", Interface.SERIAL) {
        @Override
        public HardwareClient createClient(SerialPort serialPort, HttpClientService httpClientService) throws DeviceException {
            return new JadeClient(serialPort, httpClientService);
        }
    },
    BITBOX_02("bitbox02", Interface.HID) {
        @Override
        public HardwareClient createClient(HidDevice hidDevice) throws DeviceException {
            return new BitBox02Client(hidDevice);
        }
    },
    TREZOR("trezor", Interface.WEBUSB) {
        @Override
        public HardwareClient createClient(Device device, DeviceDescriptor deviceDescriptor) throws DeviceException {
            return new TrezorClient(device, deviceDescriptor);
        }
    },
    KEEPKEY("keepkey", Interface.WEBUSB) {
        @Override
        public HardwareClient createClient(Device device, DeviceDescriptor deviceDescriptor) throws DeviceException {
            return new KeepkeyClient(device, deviceDescriptor);
        }
    },
    LEDGER("ledger", Interface.HID) {
        @Override
        public HardwareClient createClient(HidDevice hidDevice) throws DeviceException {
            return new LedgerClient(hidDevice);
        }
    };

    private final String name;
    private final Interface interfaceType;

    HardwareType(String name, Interface interfaceType) {
        this.name = name;
        this.interfaceType = interfaceType;
    }

    public String getName() {
        return name;
    }

    public String getDisplayName() {
        return name.substring(0, 1).toUpperCase() + name.substring(1).toLowerCase();
    }

    public HardwareClient createClient(HidDevice hidDevice) throws DeviceException {
        throw new DeviceException("Not an HID hardware type");
    }

    public HardwareClient createClient(SerialPort serialPort, HttpClientService httpClientService) throws DeviceException {
        throw new DeviceException("Not a serial hardware type");
    }

    public HardwareClient createClient(Device device, DeviceDescriptor descriptor) throws DeviceException {
        throw new DeviceException("Not a WebUSB hardware type");
    }

    public boolean uses(Interface interfaceType) {
        return this.interfaceType == interfaceType;
    }

    public static HardwareClient fromHidDevice(HidDevice hidDevice) throws DeviceException {
        for(HardwareType type : values()) {
            try {
                return type.createClient(hidDevice);
            } catch(DeviceException e) {
                //ignore
            }
        }

        throw new DeviceNotFoundException("No HID hardware type for vendor id: " + hidDevice.getVendorId() + ", product id: " + hidDevice.getProductId());
    }

    public static HardwareClient fromSerialPort(SerialPort serialPort, HttpClientService httpClientService) throws DeviceException {
        for(HardwareType type : values()) {
            try {
                return type.createClient(serialPort, httpClientService);
            } catch(DeviceException e) {
                //ignore
            }
        }

        throw new DeviceNotFoundException("No serial hardware type for vendor id: " + serialPort.getVendorID() + ", product id: " + serialPort.getProductID());
    }

    public static HardwareClient fromWebusbDevice(Device device, DeviceDescriptor deviceDescriptor) throws DeviceException {
        for(HardwareType type : values()) {
            try {
                return type.createClient(device, deviceDescriptor);
            } catch(DeviceException e) {
                //ignore
            }
        }

        throw new DeviceNotFoundException("No WebUSB type for vendor id: " + deviceDescriptor.idVendor() + ", product id: " + deviceDescriptor.idProduct());
    }

    public static HardwareType fromString(String name) {
        for(HardwareType type : values()) {
            if(type.name.equals(name)) {
                return type;
            }
        }

        return null;
    }
}
