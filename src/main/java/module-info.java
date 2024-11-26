open module com.sparrowwallet.lark {
    requires co.nstant.in.cbor;
    requires com.fazecast.jSerialComm;
    requires com.google.protobuf;
    requires com.sparrowwallet.drongo;
    requires com.sparrowwallet.tern;
    requires org.hid4java;
    requires com.google.code.findbugs.jsr305;
    requires org.apache.commons.codec;
    requires org.slf4j;
    requires org.usb4java;
    requires com.fasterxml.jackson.databind;
    requires com.google.common;
    exports com.sparrowwallet.lark;
}