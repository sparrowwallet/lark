package com.sparrowwallet.lark.bitbox02;

import com.sparrowwallet.lark.Platform;

import java.io.File;
import java.nio.file.Path;

public class BitBoxAppNoiseConfig extends BitBoxFileNoiseConfig {
    public BitBoxAppNoiseConfig() {
        super(getBitBoxAppConfigFile());
    }

    private static File getBitBoxAppConfigFile() {
        String configHome;
        Platform platform = Platform.getCurrent();
        if(platform == Platform.UNIX) {
            configHome = System.getenv("XDG_CONFIG_HOME");
            if(configHome == null) {
                configHome = System.getProperty("user.home") + "/.config";
            }
        } else if(platform == Platform.MACOS) {
            configHome = System.getProperty("user.home") + "/Library/Application Support";
        } else if(platform == Platform.WINDOWS) {
            configHome = System.getenv("APPDATA");
        } else {
            throw new UnsupportedOperationException("Unsupported platform: " + platform);
        }

        return Path.of(configHome, "bitbox", "bitbox02", "bitbox02.json").toFile();
    }
}
