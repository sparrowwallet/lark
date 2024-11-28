package com.sparrowwallet.lark.bitbox02;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sparrowwallet.drongo.crypto.X25519Key;
import com.sparrowwallet.lark.DeviceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

public class BitBoxFileNoiseConfig implements BitBoxNoiseConfig {
    private static final Logger log = LoggerFactory.getLogger(BitBoxAppNoiseConfig.class);

    private final ObjectMapper mapper = new ObjectMapper();

    protected final File config;

    public BitBoxFileNoiseConfig(File config) {
        this.config = config;
    }

    @Override
    public boolean showPairing(String code, DeviceResponse response) throws DeviceException {
        return response.call();
    }

    @Override
    public void attestationCheck(boolean result) {}

    @Override
    public boolean containsDeviceStaticPubkey(byte[] pubkey) {
        NoiseFileConfig noiseConfig = read();
        String base64Pubkey = Base64.getEncoder().encodeToString(pubkey);
        return noiseConfig.deviceNoiseStaticPubkeys.contains(base64Pubkey);
    }

    @Override
    public void addDeviceStaticPubkey(byte[] pubkey) {
        if(!containsDeviceStaticPubkey(pubkey)) {
            NoiseFileConfig noiseConfig = read();
            String base64Pubkey = Base64.getEncoder().encodeToString(pubkey);
            noiseConfig.deviceNoiseStaticPubkeys.add(base64Pubkey);
            write(noiseConfig);
        }
    }

    @Override
    public Optional<X25519Key> getAppStaticKey() {
        NoiseFileConfig noiseConfig = read();
        if(noiseConfig.appNoiseStaticKeypair == null) {
            return Optional.empty();
        }

        return Optional.of(new X25519Key(Base64.getDecoder().decode(noiseConfig.appNoiseStaticKeypair.privateKey)));
    }

    @Override
    public void setAppStaticKey(X25519Key x25519Key) {
        NoiseFileConfig noiseConfig = read();
        noiseConfig.appNoiseStaticKeypair = new AppNoiseKeypair();
        noiseConfig.appNoiseStaticKeypair.publicKey = Base64.getEncoder().encodeToString(x25519Key.getRawPublicKeyBytes());
        noiseConfig.appNoiseStaticKeypair.privateKey = Base64.getEncoder().encodeToString(x25519Key.getRawPrivateKeyBytes());
        write(noiseConfig);
    }

    private NoiseFileConfig read() {
        try {
            String json = Files.readString(config.toPath(), StandardCharsets.UTF_8);
            return mapper.readValue(json, NoiseFileConfig.class);
        } catch(Exception e) {
            log.info("Could not read " + config.getAbsolutePath() + ", device pairing required", e);
            return new NoiseFileConfig();
        }
    }

    private void write(NoiseFileConfig noiseConfig) {
        try {
            if(!config.exists()) {
                config.getParentFile().mkdirs();
                config.createNewFile();
            }

            mapper.writeValue(config, noiseConfig);
        } catch(Exception e) {
            log.error("Could not write " + config.getAbsolutePath(), e);
        }
    }

    public static class NoiseFileConfig {
        public AppNoiseKeypair appNoiseStaticKeypair;
        public List<String> deviceNoiseStaticPubkeys = new ArrayList<>();
    }

    public static class AppNoiseKeypair {
        @JsonProperty("private")
        public String privateKey;
        @JsonProperty("public")
        public String publicKey;
    }
}
