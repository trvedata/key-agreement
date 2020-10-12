package org.trvedata.sgm.crypto;

import djb.Curve25519;
import org.apache.thrift.TException;
import org.trvedata.sgm.message.SignatureStruct;
import org.trvedata.sgm.misc.Utils;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class IdentityKey implements Comparable<IdentityKey> {
    final byte[] curve25519PublicKey;

    public IdentityKey(byte[] serialized) {
        if (serialized.length != Curve25519.KEY_SIZE) {
            throw new IllegalArgumentException("Wrong key length: " + serialized.length);
        }
        this.curve25519PublicKey = serialized;
    }

    public boolean verify(byte[] plaintext, byte[] signature) {
        // Curve25519 is undocumented; this usage is based on
        // https://github.com/facebookresearch/asynchronousratchetingtree/blob/master/AsynchronousRatchetingTree/src/main/java/com/facebook/research/asynchronousratchetingtree/crypto/DHPubKey.java
        SignatureStruct deserialized = new SignatureStruct();
        try {
            Utils.deserialize(deserialized, signature);
        } catch (TException exc) {
            return false;
        }
        byte[] output = new byte[Curve25519.KEY_SIZE];
        Curve25519.verify(output, deserialized.getAlgOutput(),
                Utils.hash(plaintext, this.curve25519PublicKey), this.curve25519PublicKey);
        return Arrays.equals(Utils.hash(output), deserialized.getHashedPoint());
    }

    @Override
    public int compareTo(IdentityKey identityKey) {
        return ByteBuffer.wrap(this.curve25519PublicKey).compareTo(ByteBuffer.wrap(identityKey.curve25519PublicKey));
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof IdentityKey)
            return Arrays.equals(this.curve25519PublicKey, ((IdentityKey) o).curve25519PublicKey);
        else return false;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.curve25519PublicKey);
    }

    public byte[] serialize() {
        return curve25519PublicKey;
    }

    public HPKEPublicKey asHpkeKey() {
        return new HPKEPublicKey(this.curve25519PublicKey);
    }

    public static IdentityKeyPair generateKeyPair() {
        byte[] secretKey = Utils.getSecureRandomBytes(Curve25519.KEY_SIZE);
        byte[] signingKey = new byte[Curve25519.KEY_SIZE];
        byte[] publicKey = new byte[Curve25519.KEY_SIZE];
        Curve25519.keygen(publicKey, signingKey, secretKey);
        return new IdentityKeyPair(secretKey, signingKey, new IdentityKey(publicKey));
    }
}
