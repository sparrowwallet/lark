open module com.sparrowwallet.lark {
    requires co.nstant.in.cbor;
    requires com.fazecast.jSerialComm;
    requires com.google.protobuf;
    requires com.sparrowwallet.drongo;
    requires com.sparrowwallet.tern;
    requires org.hid4java;
    requires org.apache.commons.codec;
    requires org.slf4j;
    requires org.usb4java;
    requires com.fasterxml.jackson.databind;
    exports com.sparrowwallet.lark;
    exports com.sparrowwallet.lark.bitbox02;
}