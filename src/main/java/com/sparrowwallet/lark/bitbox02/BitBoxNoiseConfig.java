package com.sparrowwallet.lark.bitbox02;

import com.sparrowwallet.drongo.crypto.X25519Key;
import com.sparrowwallet.lark.DeviceException;

import java.util.Optional;

public interface BitBoxNoiseConfig {
    boolean showPairing(String code, DeviceResponse response) throws DeviceException;
    void attestationCheck(boolean result);
    boolean containsDeviceStaticPubkey(byte[] pubkey);
    void addDeviceStaticPubkey(byte[] pubkey);
    Optional<X25519Key> getAppStaticKey();
    void setAppStaticKey(X25519Key key);

    abstract class DeviceResponse {
        public abstract boolean call() throws DeviceException;
    }
}
