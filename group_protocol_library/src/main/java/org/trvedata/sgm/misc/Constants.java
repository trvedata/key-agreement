package org.trvedata.sgm.misc;

public class Constants {

    /**
     * Standard key size in bytes for this implementation.
     * We use the 128-bit security level.  Note that any larger will create a Java Cryptography Extension dependency
     * (in {@link Utils#aeadEncrypt}.
     */
    public final static int KEY_SIZE_BYTES = 16;

    private Constants() {
    }
}
