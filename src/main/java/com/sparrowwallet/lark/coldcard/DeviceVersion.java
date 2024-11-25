package com.sparrowwallet.lark.coldcard;

public record DeviceVersion(String date, String firmware, String bootloader, String dateAndTime, String hardware) {
    @Override
    public String toString() {
        return "DeviceVersion{" +
                "date='" + date + '\'' +
                ", firmware='" + firmware + '\'' +
                ", bootloader='" + bootloader + '\'' +
                ", dateAndTime='" + dateAndTime + '\'' +
                ", hardware='" + hardware + '\'' +
                '}';
    }
}
