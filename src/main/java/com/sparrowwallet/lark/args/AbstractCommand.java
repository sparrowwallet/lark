package com.sparrowwallet.lark.args;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.sparrowwallet.lark.Lark;

public abstract class AbstractCommand implements Command {
    @Parameter(names = { "--help", "-h" }, description = "Show this help message and exit", help = true)
    public boolean help;

    @Override
    public void run(JCommander jCommander, Lark lark, Args args) throws Exception {
        if(help) {
            jCommander.usage(getName());
            System.exit(0);
        }
        if(!EnumerateCommand.NAME.equals(getName())) {
            if(args.deviceType == null && args.fingerprint == null) {
                error("You must specify a device type or fingerprint for all commands except enumerate");
            }
        }
    }

    protected void success(boolean success) {
        Lark.showSuccess(success);
    }

    protected void value(Object value) {
        Lark.showValue(value);
    }

    protected void error(String errorMessage) {
        Lark.showErrorAndExit(errorMessage);
    }

    protected record XpubValue(String xpub) {}
}
