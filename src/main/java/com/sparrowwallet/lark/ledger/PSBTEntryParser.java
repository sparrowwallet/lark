package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTEntry;
import com.sparrowwallet.drongo.psbt.PSBTParseException;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static com.sparrowwallet.drongo.psbt.PSBT.*;

public class PSBTEntryParser {
    private final List<PSBTEntry> globalEntries = new ArrayList<>();
    private final List<List<PSBTEntry>> inputEntryLists = new ArrayList<>();
    private final List<List<PSBTEntry>> outputEntryLists = new ArrayList<>();

    public PSBTEntryParser(PSBT psbt) throws PSBTParseException {
        ByteBuffer psbtByteBuffer = ByteBuffer.wrap(psbt.serialize());

        byte[] magicBuf = new byte[4];
        psbtByteBuffer.get(magicBuf);
        if(!PSBT_MAGIC_HEX.equalsIgnoreCase(Utils.bytesToHex(magicBuf))) {
            throw new PSBTParseException("PSBT has invalid magic value");
        }

        byte sep = psbtByteBuffer.get();
        if(sep != (byte) 0xff) {
            throw new PSBTParseException("PSBT has bad initial separator: " + Utils.bytesToHex(new byte[]{sep}));
        }

        int currentState = STATE_GLOBALS;

        List<PSBTEntry> inputEntries = new ArrayList<>();
        List<PSBTEntry> outputEntries = new ArrayList<>();

        int seenInputs = 0;
        int seenOutputs = 0;

        while (psbtByteBuffer.hasRemaining()) {
            PSBTEntry entry = new PSBTEntry(psbtByteBuffer);

            if(entry.getKey() == null) {         // length == 0
                switch (currentState) {
                    case STATE_GLOBALS:
                        currentState = STATE_INPUTS;
                        break;
                    case STATE_INPUTS:
                        inputEntryLists.add(inputEntries);
                        inputEntries = new ArrayList<>();

                        seenInputs++;
                        if(seenInputs == psbt.getPsbtInputs().size()) {
                            currentState = STATE_OUTPUTS;
                        }
                        break;
                    case STATE_OUTPUTS:
                        outputEntryLists.add(outputEntries);
                        outputEntries = new ArrayList<>();

                        seenOutputs++;
                        if(seenOutputs == psbt.getPsbtOutputs().size()) {
                            currentState = STATE_END;
                        }
                        break;
                    case STATE_END:
                        break;
                    default:
                        throw new PSBTParseException("PSBT structure invalid");
                }
            } else if (currentState == STATE_GLOBALS) {
                globalEntries.add(entry);
            } else if (currentState == STATE_INPUTS) {
                inputEntries.add(entry);
            } else if (currentState == STATE_OUTPUTS) {
                outputEntries.add(entry);
            } else {
                throw new PSBTParseException("PSBT structure invalid");
            }
        }
    }

    public List<PSBTEntry> getGlobalEntries() {
        return globalEntries;
    }

    public List<List<PSBTEntry>> getInputEntryLists() {
        return inputEntryLists;
    }

    public List<List<PSBTEntry>> getOutputEntryLists() {
        return outputEntryLists;
    }
}
