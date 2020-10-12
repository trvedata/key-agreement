package org.trvedata.sgm.misc;

public class Preconditions {

    public static void checkArgument(final boolean predicate, final String message) {
        if (!predicate) {
            throw new IllegalArgumentException(message);
        }
    }

    public static void checkState(final boolean predicate, final String message) {
        if (!predicate) {
            throw new IllegalStateException(message);
        }
    }

}
