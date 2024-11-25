package com.sparrowwallet.lark.coldcard;

public class Constants {

    // For upload/download this is the max size of the data block.
    public static final int MAX_BLK_LEN = 2048;

    // Max total message length, excluding framing overhead (1 byte per 64).
    // - includes args for upload command
    public static final int MAX_MSG_LEN = 4 + 4 + 4 + MAX_BLK_LEN;

    // Max PSBT txn we support (384k bytes as PSBT)
    // - the max on the wire for mainnet is 100k
    // - but a PSBT might contain a full txn for each input
    public static final int MAX_TXN_LEN = 384 * 1024;

    // Max size of any upload (firmware.dfu files in particular)
    public static final int MAX_UPLOAD_LEN = 2 * MAX_TXN_LEN;

    // Max length of text messages for signing
    public static final int MSG_SIGNING_MAX_LENGTH = 240;

    // Types of user auth we support
    public static final int USER_AUTH_TOTP = 1;       // RFC6238
    public static final int USER_AUTH_HOTP = 2;       // RFC4226
    public static final int USER_AUTH_HMAC = 3;       // PBKDF2('hmac-sha256', secret, sha256(psbt), PBKDF2_ITER_COUNT)
    public static final int USER_AUTH_SHOW_QR = 0x80; // show secret on Coldcard screen (best for TOTP enroll)

    public static final int MAX_USERNAME_LEN = 16;
    public static final int PBKDF2_ITER_COUNT = 2500;

    // Max depth for derived keys, in PSBT files, and USB commands
    public static final int MAX_PATH_DEPTH = 12;

    // Bitmask used in sign_transaction (stxn) command
    public static final int STXN_FINALIZE = 0x01;
    public static final int STXN_VISUALIZE = 0x02;
    public static final int STXN_SIGNED = 0x04;
    public static final int STXN_FLAGS_MASK = 0x07;

    // Bit values for address types
    public static final int AFC_PUBKEY = 0x01;        // pay to hash of pubkey
    public static final int AFC_SEGWIT = 0x02;        // requires a witness to spend
    public static final int AFC_BECH32 = 0x04;        // just how we're encoding it?
    public static final int AFC_SCRIPT = 0x08;        // paying into a script
    public static final int AFC_WRAPPED = 0x10;       // for transition/compat types for segwit vs. old

    // Numeric codes for specific address types
    public static final int AF_CLASSIC = AFC_PUBKEY;          // 1addr
    public static final int AF_P2SH = AFC_SCRIPT;             // classic multisig / simple P2SH / 3hash
    public static final int AF_P2WPKH = AFC_PUBKEY | AFC_SEGWIT | AFC_BECH32;     // bc1qsdklfj
    public static final int AF_P2WSH = AFC_SCRIPT | AFC_SEGWIT | AFC_BECH32;     // segwit multisig
    public static final int AF_P2WPKH_P2SH = AFC_WRAPPED | AFC_PUBKEY | AFC_SEGWIT;    // looks classic P2SH, but p2wpkh inside
    public static final int AF_P2WSH_P2SH = AFC_WRAPPED | AFC_SCRIPT | AFC_SEGWIT;     // looks classic P2SH, segwit multisig

    public static final int[] SUPPORTED_ADDR_FORMATS = {
            AF_CLASSIC,
            AF_P2SH,
            AF_P2WPKH,
            AF_P2WSH,
            AF_P2WPKH_P2SH,
            AF_P2WSH_P2SH,
    };

    // BIP-174 aka PSBT defined values
    public static final int PSBT_GLOBAL_UNSIGNED_TX = 0;
    public static final int PSBT_GLOBAL_XPUB = 1;

    public static final int PSBT_IN_NON_WITNESS_UTXO = 0;
    public static final int PSBT_IN_WITNESS_UTXO = 1;
    public static final int PSBT_IN_PARTIAL_SIG = 2;
    public static final int PSBT_IN_SIGHASH_TYPE = 3;
    public static final int PSBT_IN_REDEEM_SCRIPT = 4;
    public static final int PSBT_IN_WITNESS_SCRIPT = 5;
    public static final int PSBT_IN_BIP32_DERIVATION = 6;
    public static final int PSBT_IN_FINAL_SCRIPTSIG = 7;
    public static final int PSBT_IN_FINAL_SCRIPTWITNESS = 8;

    public static final int PSBT_OUT_REDEEM_SCRIPT = 0;
    public static final int PSBT_OUT_WITNESS_SCRIPT = 1;
    public static final int PSBT_OUT_BIP32_DERIVATION = 2;

}
