package com.sparrowwallet.lark.bitbox02;

public enum BitBox02Edition {
    MULTI("multi", "BitBox02"),
    BTCONLY("btconly", "BitBox02BTC"),
    NOVA_MULTI("novamulti", "BitBox02 Nova Multi"),
    NOVA_BTCONLY("novabtconly", "BitBox02 Nova BTC-only");

    private final String name;
    private final String productString;

    BitBox02Edition(String name, String productString) {
        this.name = name;
        this.productString = productString;
    }

    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return name;
    }

    public static BitBox02Edition fromProductString(String productString) {
        for(BitBox02Edition edition : values()) {
            if(edition.productString.equals(productString)) {
                return edition;
            }
        }

        return null;
    }
}
