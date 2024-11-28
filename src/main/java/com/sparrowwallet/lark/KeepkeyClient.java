package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.lark.trezor.TrezorDevice;
import com.sparrowwallet.lark.trezor.TrezorModel;
import org.usb4java.Device;
import org.usb4java.DeviceDescriptor;

import java.util.List;

public class KeepkeyClient extends TrezorClient {
    public static final List<DeviceId> KEEPKEY_DEVICE_IDS = List.of(new DeviceId(0x2B24, 0x0002));

    public KeepkeyClient(Device device, DeviceDescriptor deviceDescriptor) throws DeviceException {
        super(KEEPKEY_DEVICE_IDS, device, deviceDescriptor, TrezorModel.KEEPKEY);
    }

    @Override
    public HardwareType getHardwareType() {
        return HardwareType.KEEPKEY;
    }

    @Override
    public WalletModel getModel() {
        return WalletModel.KEEPKEY;
    }

    @Override
    public boolean canSignTaproot(TrezorDevice trezorDevice) {
        return false;
    }
}
