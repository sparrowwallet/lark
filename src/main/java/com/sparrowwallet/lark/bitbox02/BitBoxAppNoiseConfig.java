package com.sparrowwallet.lark.bitbox02;

import com.sparrowwallet.drongo.OsType;

import java.io.File;
import java.nio.file.Path;

public class BitBoxAppNoiseConfig extends BitBoxFileNoiseConfig {
    public BitBoxAppNoiseConfig() {
        super(getBitBoxAppConfigFile());
    }

    private static File getBitBoxAppConfigFile() {
        String configHome;
        OsType osType = OsType.getCurrent();
        if(osType == OsType.UNIX) {
            configHome = System.getenv("XDG_CONFIG_HOME");
            if(configHome == null) {
                configHome = System.getProperty("user.home") + "/.config";
            }
        } else if(osType == OsType.MACOS) {
            configHome = System.getProperty("user.home") + "/Library/Application Support";
        } else if(osType == OsType.WINDOWS) {
            configHome = System.getenv("APPDATA");
        } else {
            throw new UnsupportedOperationException("Unsupported platform: " + osType);
        }

        return Path.of(configHome, "bitbox", "bitbox02", "bitbox02.json").toFile();
    }
}
