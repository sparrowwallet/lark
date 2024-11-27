package com.sparrowwallet.lark;

import org.usb4java.Context;
import org.usb4java.LibUsb;

import java.io.Closeable;

public class LarkContext implements Closeable {
    private final Context context;

    public LarkContext() {
        this.context = new Context();
        LibUsb.init(context);
    }

    public Context getContext() {
        return context;
    }

    @Override
    public void close() {
        if(context.getPointer() != 0) {
            LibUsb.exit(context);
        }
    }
}
