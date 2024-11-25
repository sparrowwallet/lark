package com.sparrowwallet.lark.coldcard;

import java.nio.charset.StandardCharsets;

public abstract class Protocol {
    protected static final int MAX_MSG_LEN = 2000;
    protected static final int MAX_USERNAME_LEN = 30;

    protected static final int AFC_PUBKEY = 0x01;       // pay to hash of pubkey
    protected static final int AFC_SEGWIT = 0x02;       // requires a witness to spend
    protected static final int AFC_BECH32 = 0x04;       // just how we're encoding it?
    protected static final int AFC_SCRIPT = 0x08;       // paying into a script
    protected static final int AFC_WRAPPED = 0x10;      // for transition/compat types for segwit vs. old

    public static final int AF_CLASSIC      = AFC_PUBKEY;          // 1addr
    public static final int AF_P2SH         = AFC_SCRIPT;          // classic multisig / simple P2SH / 3hash
    public static final int AF_P2WPKH       = AFC_PUBKEY  | AFC_SEGWIT | AFC_BECH32;     // bc1qsdklfj
    public static final int AF_P2WSH        = AFC_SCRIPT  | AFC_SEGWIT | AFC_BECH32;     // segwit multisig
    public static final int AF_P2WPKH_P2SH  = AFC_WRAPPED | AFC_PUBKEY | AFC_SEGWIT;     // looks classic P2SH, but p2wpkh inside
    public static final int AF_P2WSH_P2SH   = AFC_WRAPPED | AFC_SCRIPT | AFC_SEGWIT;     // looks classic P2SH, segwit multisig

    protected static final int STXN_FINALIZE = 1;
    protected static final byte[] LOGO = "logo".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] REBO = "rebo".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] VERS = "vers".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] PING = "ping".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] PASS = "pass".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] PWOK = "pwok".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] MITM = "mitm".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] BACK = "back".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] NCRY = "ncry".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] UPLD = "upld".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] DWLD = "dwld".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] SHA2 = "sha2".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] STXN = "stxn".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] SMSG = "smsg".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] SMOK = "smok".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] BKOK = "bkok".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] STOK = "stok".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] ENRL = "enrl".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] MSCK = "msck".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] XPUB = "xpub".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] SHOW = "show".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] P2SH = "p2sh".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] BLKC = "blkc".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] XKEY = "XKEY".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] BAGI = "bagi".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] HSMS = "hsms".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] HSTS = "hsts".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] NWUR = "nwur".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] RMUR = "rmur".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] USER = "user".getBytes(StandardCharsets.UTF_8);
    protected static final byte[] GSLR = "gslr".getBytes(StandardCharsets.UTF_8);
}
