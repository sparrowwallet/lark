package com.sparrowwallet.lark.jade;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.sparrowwallet.drongo.Version;

@JsonIgnoreProperties(ignoreUnknown = true)
public record JadeVersion(Version JADE_VERSION, int JADE_OTA_MAX_CHUNK, String JADE_CONFIG, String BOARD_TYPE, String JADE_FEATURES,
                          String IDF_VERSION, String CHIP_FEATURES, String EFUSEMAC, int BATTERY_STATUS, JadeState JADE_STATE, JadeNetwork JADE_NETWORKS, boolean JADE_HAS_PIN) {
}
