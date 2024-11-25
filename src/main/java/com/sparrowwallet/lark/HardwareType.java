package com.sparrowwallet.lark;

import com.fazecast.jSerialComm.SerialPort;
import com.sparrowwallet.tern.http.client.HttpClientService;
import org.hid4java.HidDevice;
import org.usb4java.Device;
import org.usb4java.DeviceDescriptor;

public enum HardwareType {
    COLDCARD("coldcard") {
        @Override
        public HardwareClient createClient(HidDevice hidDevice) throws DeviceException {
            return new ColdcardClient(hidDevice);
        }
    },
    JADE("jade") {
        @Override
        public HardwareClient createClient(SerialPort serialPort, HttpClientService httpClientService) throws DeviceException {
            return new JadeClient(serialPort, httpClientService);
        }
    },
    BITBOX_02("bitbox02") {
        @Override
        public HardwareClient createClient(HidDevice hidDevice) throws DeviceException {
            return new BitBox02Client(hidDevice);
        }
    },
    TREZOR("trezor") {
        @Override
        public HardwareClient createClient(Device device, DeviceDescriptor deviceDescriptor) throws DeviceException {
            return new TrezorClient(device, deviceDescriptor);
        }
    },
    KEEPKEY("keepkey") {
        @Override
        public HardwareClient createClient(Device device, DeviceDescriptor deviceDescriptor) throws DeviceException {
            return new KeepkeyClient(device, deviceDescriptor);
        }
    },
    LEDGER("ledger") {
        @Override
        public HardwareClient createClient(HidDevice hidDevice) throws DeviceException {
            return new LedgerClient(hidDevice);
        }
    };

    private final String name;

    HardwareType(String name) {
        this.name = name;
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
}
