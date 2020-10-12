package org.trvedata.sgm;

import org.apache.thrift.TException;
import org.pcollections.HashPMap;
import org.pcollections.HashTreePMap;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.message.VectorClockMessage;
import org.trvedata.sgm.misc.Utils;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

public class VectorClock {
    private final IdentityKey sender;
    private final HashPMap<IdentityKey, Integer> clock;

    public VectorClock(IdentityKey sender, HashPMap<IdentityKey, Integer> clock) {
        this.sender = sender;
        this.clock = clock;
    }

    public VectorClock(byte[] serialized) {
        try {
            VectorClockMessage deserialized = new VectorClockMessage();
            Utils.deserialize(deserialized, serialized);
            sender = new IdentityKey(deserialized.getSender());
            HashPMap<IdentityKey, Integer> clockConstructor = HashTreePMap.empty();
            for (Map.Entry<ByteBuffer, Integer> entry : deserialized.getClock().entrySet()) {
                clockConstructor = clockConstructor.plus(new IdentityKey(Utils.asArray(entry.getKey())), entry.getValue());
            }
            this.clock = clockConstructor;
        } catch (TException | IllegalArgumentException exc) {
            throw new IllegalArgumentException("Failed to deserialize VectorClock", exc);
        }
    }

    public VectorClock increment(IdentityKey member) {
        return new VectorClock(member, clock.plus(member, 1 + get(member)));
    }

    /**
     * Returns the number of messages processed from {@code member} so far.
     */
    public int get(IdentityKey member) {
        return clock.getOrDefault(member, 0);
    }

    public IdentityKey getSender() {
        return sender;
    }

    public boolean isGeq(VectorClock other) {
        return (this.get(other.sender) >= other.get(other.sender));
    }

    public boolean isConcurrent(VectorClock other) {
        return !(this.isGeq(other) || other.isGeq(this));
    }

    public byte[] serialize() {
        HashMap<ByteBuffer, Integer> buffered = new HashMap<>();
        for (Map.Entry<IdentityKey, Integer> entry : clock.entrySet()) {
            buffered.put(ByteBuffer.wrap(entry.getKey().serialize()), entry.getValue());
        }
        return Utils.serialize(new VectorClockMessage(ByteBuffer.wrap(sender.serialize()), buffered));
    }

    public String toString() {
        StringBuilder ret = new StringBuilder("(" + sender.hashCode() + ", {");
        for (Map.Entry<IdentityKey, Integer> entry : clock.entrySet()) {
            ret.append(entry.getKey().hashCode() + ": " + entry.getValue() + ",");
        }
        ret.append("})");
        return ret.toString();
    }
}
