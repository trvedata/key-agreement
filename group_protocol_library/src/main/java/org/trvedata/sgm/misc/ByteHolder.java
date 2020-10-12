package org.trvedata.sgm.misc;

public class ByteHolder {
    private final byte[] bytes;

    public ByteHolder(final byte[] bytes) {
        this.bytes = bytes;
    }

    public final byte[] getBytes() {
        return bytes;
    }
}
