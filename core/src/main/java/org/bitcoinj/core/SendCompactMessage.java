package org.bitcoinj.core;

public class SendCompactMessage extends EmptyMessage {
    public SendCompactMessage() {
    }

    // this is needed by the BitcoinSerializer
    public SendCompactMessage(NetworkParameters params, byte[] payload) {
    }
}
