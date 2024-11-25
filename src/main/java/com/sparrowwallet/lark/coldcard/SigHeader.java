package com.sparrowwallet.lark.coldcard;

public class SigHeader {

    public static final int FW_HEADER_SIZE = 128;
    public static final int FW_HEADER_OFFSET = (0x4000 - FW_HEADER_SIZE);

    public static final long FW_HEADER_MAGIC = 0xCC001234;

    // arbitrary min size
    public static final int FW_MIN_LENGTH = (256 * 1024);
    // absolute max: 1MB flash - 32k for bootloader
    // practical limit for our-protocol USB upgrades: 786432 (or else settings damaged)
    public static final int FW_MAX_LENGTH = (0x100000 - 0x8000);

    public static final String FWH_PY_FORMAT = "<I8s8sII36s64s";
    public static final String FWH_PY_VALUES = "magic_value timestamp version_string pubkey_num firmware_length future signature";
    public static final int FWH_NUM_FUTURE = 9;
    public static final int FWH_PK_NUM_OFFSET = 20;

    // There is a copy of the header at this location in RAM, copied by bootloader
    // **after** it has been verified. Cannot write to this area, or you will be reset!
    public static final int RAM_HEADER_BASE = 0x10007c20;

    // Original copy of header, as recorded in flash/firmware file.
    public static final int FLASH_HEADER_BASE = 0x0800bf80;

}
