package com.sparrowwallet.lark.bitbox02;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class AttestationKeys {
    public static Map<Sha256Hash, AttestationPubkeyInfo> getPubKeysMap() {
        return getAttestationPubkeys().stream().collect(Collectors.toMap(pubKeyInfo -> Sha256Hash.of(pubKeyInfo.getPubkey()), Function.identity(), (u, v) -> u, LinkedHashMap::new));
    }

    public static List<AttestationPubkeyInfo> getAttestationPubkeys() {
        List<AttestationPubkeyInfo> attestationPubkeys = new ArrayList<>();

        attestationPubkeys.add(new AttestationPubkeyInfo(
                Utils.hexToBytes("04074ff1273b36c24e80fe3d59e0e897a81732d3f8e9cd07e17e9fc06319cd16b25cf74255674477b3ac9cbac2d12f0dc27a662681fcbc12955b0bccdcbbdcfd01"),
                null
        ));

        attestationPubkeys.add(new AttestationPubkeyInfo(
                Utils.hexToBytes("044c53a84f41fa7301b378bb3c260fc9b2ff1cbea7a78181279a8566797a736f12cea25fa2b1c27a844392fe9b37547dc6fbd00a2676b816e7d2d3562be2a0cbbd"),
                null
        ));

        attestationPubkeys.add(new AttestationPubkeyInfo(
                Utils.hexToBytes("04e9c8dc929796aac65af5084eb54dc1ee482d5e0b5c58e2c93f243c5b70b21523324bdb78d7395317da165ef1138826c3ca3c91ca95e6f490c340cf5508a4a3ec"),
                null
        ));

        attestationPubkeys.add(new AttestationPubkeyInfo(
                Utils.hexToBytes("04c2fb05889b9dff5a9fb22a59ee1d16bfc2863f0400ddcb69566e2abe8a15fa0ba1240254ca45aa310d170e724e1310ce5f611cada76c12e3c24a926a390ca4be"),
                null
        ));

        attestationPubkeys.add(new AttestationPubkeyInfo(
                Utils.hexToBytes("04c4e82d6d1b91e7853eba96a871ad31fc62620b826b0b8acf815c03de31b792a98e05bb34d3b9e0df1040eac485f03ff8bbbf7a857ef1cf2a49a60ac084efb88f"),
                null
        ));

        attestationPubkeys.add(new AttestationPubkeyInfo(
                Utils.hexToBytes("040526f5b8348a8d55e7b1cac043ce98c55bbdb3311b4d1bb2d654281edf8aeb21f018fb027a6b08e4ddc62c919e648690722d00c6f54c668c9bd8224a1d82423a"),
                Utils.hexToBytes("e8fa0bd5fc80b86b9f1ea983664df33b27f6f95855d79fb43248ee4c3d3e6be6")
        ));

        attestationPubkeys.add(new AttestationPubkeyInfo(
                Utils.hexToBytes("0422491e19766bd96a56e3f2f3926a6c57b89209ff47bd10e523b223ff65ab9af11c0a5f62c187514f2117ce772de90f9901ee122af78e69bbc4d29eec811be8ec"),
                null
        ));

        attestationPubkeys.add(new AttestationPubkeyInfo(
                Utils.hexToBytes("049f1b7180014b6de60d41f16a3c0a37b20146585e4884960249d30f3cd68c74d04420d0cedef5719d6b1529b085ecd534fa6c1690be5eb1b3331bc57b5db224dc"),
                null
        ));

        attestationPubkeys.add(new AttestationPubkeyInfo(
                Utils.hexToBytes("04adaa011a4ced11310728abb64f09636267ce0b05782da6d3eeaf987cec7c64f279ad55327184f9e5b4a1e53089b31bcc65032dad7205325f41ed3d9fdfba1f88"),
                null
        ));

        attestationPubkeys.add(new AttestationPubkeyInfo(
                Utils.hexToBytes("044a70e663d7fe5fe0d4cbbb752883e35222b8d7d7bffdaa8d591995d1252528a4e9a3e4d5220d485021728b3cdad4fccc681a6ddeea8e2f7c55b4acde8d53573d"),
                null
        ));

        return attestationPubkeys;
    }

    public static class AttestationPubkeyInfo {
        private final byte[] pubkey;
        private final byte[] acceptedBootloaderHash;

        public AttestationPubkeyInfo(byte[] pubkey, byte[] acceptedBootloaderHash) {
            this.pubkey = pubkey;
            this.acceptedBootloaderHash = acceptedBootloaderHash;
        }

        public byte[] getPubkey() {
            return pubkey;
        }

        public byte[] getAcceptedBootloaderHash() {
            return acceptedBootloaderHash;
        }
    }
}
