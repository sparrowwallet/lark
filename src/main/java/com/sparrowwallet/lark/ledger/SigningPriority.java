package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.drongo.protocol.ScriptType;

import java.util.List;

public enum SigningPriority {
    PRIORITY_0(List.of(ScriptType.P2TR)),
    PRIORITY_1(List.of(ScriptType.P2WPKH, ScriptType.P2WSH)),
    PRIORITY_2(List.of(ScriptType.P2SH_P2WPKH, ScriptType.P2SH_P2WSH)),
    PRIORITY_3(List.of(ScriptType.P2PKH, ScriptType.P2SH));

    private final List<ScriptType> scriptTypes;

    SigningPriority(List<ScriptType> scriptTypes) {
        this.scriptTypes = scriptTypes;
    }

    public static SigningPriority fromScriptType(ScriptType scriptType) {
        for(SigningPriority priority : SigningPriority.values()) {
            if(priority.scriptTypes.contains(scriptType)) {
                return priority;
            }
        }

        throw new IllegalArgumentException("Unknown script type: " + scriptType);
    }
}
