package com.sparrowwallet.lark.trezor;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.stream.Collectors;

/**
 * File-based credential storage matching BitBoxFileNoiseConfig pattern.
 * Stores credentials as JSON with Base64 encoding for binary data.
 *
 * Default location: ~/.lark/trezor_thp_credentials.json
 */
public class TrezorFileNoiseConfig implements TrezorNoiseConfig {
    private static final Logger log = LoggerFactory.getLogger(TrezorFileNoiseConfig.class);

    private final ObjectMapper mapper = new ObjectMapper();
    private final File configFile;

    /**
     * Create a credential store with the specified file.
     *
     * @param configFile The file to store credentials (typically ~/.lark/trezor_thp_credentials.json)
     */
    public TrezorFileNoiseConfig(File configFile) {
        this.configFile = configFile;
    }

    /**
     * Create a credential store with default location.
     * Default: ~/.lark/trezor_thp_credentials.json
     */
    public TrezorFileNoiseConfig() {
        this(getDefaultConfigFile());
    }

    private static File getDefaultConfigFile() {
        String userHome = System.getProperty("user.home");
        return new File(userHome, ".lark/trezor_thp_credentials.json");
    }

    @Override
    public boolean containsCredential(byte[] trezorPublicKey) {
        ThpCredentialConfig config = read();
        String base64Key = Base64.getEncoder().encodeToString(trezorPublicKey);
        return config.credentials.containsKey(base64Key);
    }

    @Override
    public void addCredential(byte[] trezorPublicKey, byte[] credentialBlob) {
        ThpCredentialConfig config = read();
        String base64Key = Base64.getEncoder().encodeToString(trezorPublicKey);
        String base64Credential = Base64.getEncoder().encodeToString(credentialBlob);

        StoredCredential credential = new StoredCredential();
        credential.credentialBlob = base64Credential;
        credential.createdAt = System.currentTimeMillis();

        config.credentials.put(base64Key, credential);
        write(config);
    }

    @Override
    public Optional<byte[]> getCredential(byte[] trezorPublicKey) {
        ThpCredentialConfig config = read();
        String base64Key = Base64.getEncoder().encodeToString(trezorPublicKey);
        StoredCredential credential = config.credentials.get(base64Key);

        if(credential == null || credential.credentialBlob == null) {
            return Optional.empty();
        }

        try {
            byte[] credentialBlob = Base64.getDecoder().decode(credential.credentialBlob);
            return Optional.of(credentialBlob);
        } catch(IllegalArgumentException e) {
            log.error("Invalid Base64 in stored credential", e);
            return Optional.empty();
        }
    }

    @Override
    public List<CredentialMatcher.StoredCredential> getAllCredentials() {
        ThpCredentialConfig config = read();
        byte[] hostPrivkey = getHostStaticPrivateKey().orElse(null);
        if(hostPrivkey == null) {
            return Collections.emptyList();
        }

        List<CredentialMatcher.StoredCredential> result = new ArrayList<>();
        for(Map.Entry<String, StoredCredential> entry : config.credentials.entrySet()) {
            try {
                byte[] trezorPubkey = Base64.getDecoder().decode(entry.getKey());
                byte[] credentialBlob = Base64.getDecoder().decode(entry.getValue().credentialBlob);
                result.add(new CredentialMatcher.StoredCredential(
                    trezorPubkey,
                    hostPrivkey,
                    credentialBlob
                ));
            } catch(IllegalArgumentException e) {
                log.error("Invalid Base64 in stored credential", e);
            }
        }
        return result;
    }

    @Override
    public Optional<byte[]> getHostStaticPrivateKey() {
        ThpCredentialConfig config = read();
        if(config.hostStaticKeypair == null || config.hostStaticKeypair.privateKey == null) {
            return Optional.empty();
        }

        try {
            byte[] privateKey = Base64.getDecoder().decode(config.hostStaticKeypair.privateKey);
            return Optional.of(privateKey);
        } catch(IllegalArgumentException e) {
            log.error("Invalid Base64 in stored host private key", e);
            return Optional.empty();
        }
    }

    @Override
    public void setHostStaticPrivateKey(byte[] privateKey) {
        ThpCredentialConfig config = read();
        config.hostStaticKeypair = new HostStaticKeypair();
        config.hostStaticKeypair.privateKey = Base64.getEncoder().encodeToString(privateKey);
        write(config);
    }

    @Override
    public void removeCredential(byte[] trezorPublicKey) {
        ThpCredentialConfig config = read();
        String base64Key = Base64.getEncoder().encodeToString(trezorPublicKey);
        config.credentials.remove(base64Key);
        write(config);
    }

    @Override
    public List<byte[]> listTrezorPublicKeys() {
        ThpCredentialConfig config = read();
        return config.credentials.keySet().stream()
                .map(base64Key -> Base64.getDecoder().decode(base64Key))
                .collect(Collectors.toList());
    }

    @Override
    public void clearAll() {
        ThpCredentialConfig config = new ThpCredentialConfig();
        write(config);
    }

    @Override
    public String getHostName() {
        try {
            return java.net.InetAddress.getLocalHost().getHostName();
        } catch(Exception e) {
            log.warn("Failed to get system hostname, using default", e);
            return "localhost";
        }
    }

    private ThpCredentialConfig read() {
        try {
            if(!configFile.exists()) {
                return new ThpCredentialConfig();
            }

            String json = Files.readString(configFile.toPath(), StandardCharsets.UTF_8);
            return mapper.readValue(json, ThpCredentialConfig.class);
        } catch(Exception e) {
            if(log.isInfoEnabled()) {
                log.info("Could not read " + configFile.getAbsolutePath() + ", starting fresh", e);
            }
            return new ThpCredentialConfig();
        }
    }

    private void write(ThpCredentialConfig config) {
        try {
            if(!configFile.exists()) {
                configFile.getParentFile().mkdirs();
                configFile.createNewFile();
            }

            mapper.writerWithDefaultPrettyPrinter().writeValue(configFile, config);
        } catch(Exception e) {
            log.error("Could not write " + configFile.getAbsolutePath(), e);
        }
    }

    /**
     * JSON structure for credential storage.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ThpCredentialConfig {
        @JsonProperty("hostStaticKeypair")
        public HostStaticKeypair hostStaticKeypair;

        @JsonProperty("credentials")
        public Map<String, StoredCredential> credentials = new LinkedHashMap<>();
    }

    /**
     * Host's static key pair (only private key is stored).
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class HostStaticKeypair {
        @JsonProperty("private")
        public String privateKey;  // Base64-encoded 32-byte X25519 private key
    }

    /**
     * Stored credential for a Trezor device.
     * Key is Base64-encoded Trezor static public key.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class StoredCredential {
        @JsonProperty("credential")
        public String credentialBlob;  // Base64-encoded credential from Trezor

        @JsonProperty("createdAt")
        public Long createdAt;  // Unix timestamp (milliseconds)
    }
}
