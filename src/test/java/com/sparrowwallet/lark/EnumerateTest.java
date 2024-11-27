package com.sparrowwallet.lark;

import org.junit.jupiter.api.Test;

import java.util.List;

public class EnumerateTest {
    @Test
    public void testEnumerate() {
        Lark lark = new Lark();
        List<HardwareClient> clients = lark.enumerate();
        for(HardwareClient client : clients) {
            System.out.println(client.getType() + " " + client.getPath());
        }
    }
}
