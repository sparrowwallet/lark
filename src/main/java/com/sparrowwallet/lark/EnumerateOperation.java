package com.sparrowwallet.lark;

import java.util.ArrayList;
import java.util.List;

public class EnumerateOperation implements ClientOperation {
    private final List<HardwareClient> clients = new ArrayList<>();

    @Override
    public boolean requires(Interface interfaceType) {
        return true;
    }

    @Override
    public boolean matches(HardwareClient hardwareClient) {
        return true;
    }

    @Override
    public void apply(HardwareClient hardwareClient) throws DeviceException {
        clients.add(hardwareClient);
    }

    public List<HardwareClient> getHardwareClients() {
        return clients;
    }
}
