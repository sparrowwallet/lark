package com.sparrowwallet.lark;

import com.fazecast.jSerialComm.SerialPort;
import org.hid4java.HidDevice;
import org.usb4java.DeviceDescriptor;

public class DeviceId {
    private final int vendorId;
    private final int productId;

    public DeviceId(int vendorId, int productId) {
        this.vendorId = vendorId;
        this.productId = productId;
    }

    public int getVendorId() {
        return vendorId;
    }

    public int getProductId() {
        return productId;
    }

    public boolean matches(HidDevice hidDevice) {
        return hidDevice.getVendorId() == vendorId && hidDevice.getProductId() == productId;
    }

    public boolean matches(SerialPort serialPort) {
        return serialPort.getVendorID() == vendorId && serialPort.getProductID() == productId;
    }

    public boolean matches(DeviceDescriptor deviceDescriptor) {
        return deviceDescriptor.idVendor() == vendorId && deviceDescriptor.idProduct() == productId;
    }

    @Override
    public String toString() {
        return "DeviceId{" +
                "vendorId=" + getVendorId() +
                ", productId=" + getProductId() +
                '}';
    }
}
