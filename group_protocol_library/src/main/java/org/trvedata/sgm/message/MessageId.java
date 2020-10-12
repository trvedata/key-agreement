package org.trvedata.sgm.message;

import org.trvedata.sgm.crypto.IdentityKey;

public final class MessageId {
    public final IdentityKey author;
    public final int number;

    public MessageId(IdentityKey author, int number) {
        this.author = author;
        this.number = number;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof MessageId)) return false;
        MessageId other = (MessageId) o;
        return (author.equals(other.author) && (number == other.number));
    }

    @Override
    public int hashCode() {
        int hashCode = 1;
        hashCode = hashCode * 8191 + author.hashCode();
        hashCode = hashCode * 8191 + number;
        return hashCode;
    }

    @Override
    public String toString() {
        return "(" + author.hashCode() + ", " + number + ")";
    }
}
