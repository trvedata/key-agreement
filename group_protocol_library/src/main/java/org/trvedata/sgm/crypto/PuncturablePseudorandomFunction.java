package org.trvedata.sgm.crypto;

import org.apache.commons.lang3.tuple.Pair;
import org.pcollections.HashPMap;
import org.pcollections.HashTreePMap;
import org.trvedata.sgm.misc.Utils;

import java.nio.ByteBuffer;
import java.util.HashMap;

/**
 * Simple implementation of a puncturable pseudorandom function (PPRF)
 * Value of input given seed is H(input + seed).
 * I think this was formalized in "Session Resumption Protocols and Efficient Forward Security for TLS 1.3 0-RTT"
 * by Nimrod Aviram, Kai Gellert, and Tibor Jager.
 * Immutable implementation.
 */
public class PuncturablePseudorandomFunction {

    private final HashPMap<ByteBuffer, byte[]> values;

    /**
     * Initializes with the given seed and set of possible inputs.
     */
    public PuncturablePseudorandomFunction(final byte[] seed, final Iterable<byte[]> inputs) {
        HashMap<ByteBuffer, byte[]> valuesConstructor = new HashMap<>();
        for (byte[] input : inputs) {
            valuesConstructor.put(ByteBuffer.wrap(input), Utils.hash(input, seed));
        }
        values = HashTreePMap.from(valuesConstructor);
    }

    private PuncturablePseudorandomFunction(HashPMap<ByteBuffer, byte[]> values) {
        this.values = values;
    }

    /**
     * Returns the value associated to input and deletes that value.  Note that this return value
     * is by-reference.  Throws IllegalArgumentException on unrecognized input.
     */
    public Pair<PuncturablePseudorandomFunction, byte[]> popValue(final byte[] input) {
        byte[] output = values.get(ByteBuffer.wrap(input));
        if (output == null) throw new IllegalArgumentException("Unrecognized input");
        return Pair.of(new PuncturablePseudorandomFunction(values.minus(ByteBuffer.wrap(input))), output);
    }

    /**
     * Returns true if there are no undeleted values left.
     */
    public boolean isEmpty() {
        return values.isEmpty();
    }
}
