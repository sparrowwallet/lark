package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.TransactionOutput;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTOutput;
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
    PSBT signTransaction(PSBT psbt) throws DeviceException {
        for(TransactionOutput out : psbt.getTransaction().getOutputs()) {
            if(ScriptType.P2TR.isScriptType(out.getScript())) {
                throw new DeviceException("The Keepkey does not support sending to Taproot addresses");
            }
        }

        return super.signTransaction(psbt);
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
    public String getProductModel() {
        return "keepkey";
    }

    @Override
    public boolean canSignTaproot(TrezorDevice trezorDevice) {
        return false;
    }
}
