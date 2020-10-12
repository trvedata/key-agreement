package org.trvedata.sgm.crypto;

import djb.Curve25519;
import org.trvedata.sgm.message.SignatureStruct;
import org.trvedata.sgm.misc.Utils;

import java.nio.ByteBuffer;

public class IdentityKeyPair {
    final byte[] curve25519SecretKey, curve25519SigningKey;
    final IdentityKey publicKey;

    /* package */ IdentityKeyPair(byte[] curve25519SecretKey, byte[] curve25519SigningKey, IdentityKey publicKey) {
        this.curve25519SecretKey = curve25519SecretKey;
        this.curve25519SigningKey = curve25519SigningKey;
        this.publicKey = publicKey;
    }

    public byte[] sign(byte[] plaintext) {
        // Curve25519 is undocumented; this usage is based on
        // https://github.com/facebookresearch/asynchronousratchetingtree/blob/master/AsynchronousRatchetingTree/src/main/java/com/facebook/research/asynchronousratchetingtree/crypto/DHKeyPair.java
        byte[] algOutput = null;
        boolean success = false;
        IdentityKeyPair ephemeralKeyPair = null;
        while (!success) {
            ephemeralKeyPair = IdentityKey.generateKeyPair();
            algOutput = new byte[Curve25519.KEY_SIZE];
            success = Curve25519.sign(algOutput, Utils.hash(plaintext, this.publicKey.curve25519PublicKey),
                    ephemeralKeyPair.curve25519SecretKey, this.curve25519SigningKey);
        }

        return Utils.serialize(new SignatureStruct(ByteBuffer.wrap(algOutput),
                ByteBuffer.wrap(Utils.hash(ephemeralKeyPair.publicKey.curve25519PublicKey))));
    }

    public IdentityKey getPublicKey() {
        return this.publicKey;
    }

    public HPKESecretKey asHpkeSecretKey() {
        return new HPKESecretKey(this.curve25519SecretKey);
    }
}
