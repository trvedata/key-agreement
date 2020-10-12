package org.trvedata.sgm.crypto;

import djb.Curve25519;
import org.apache.commons.lang3.tuple.Pair;
import org.trvedata.sgm.message.HPKEMessage;
import org.trvedata.sgm.misc.Utils;

import java.nio.ByteBuffer;

/**
 * Public key for a hybrid public key encryption scheme, using Diffie-Hellman
 * with Curve 25519 to generate a one-time symmetric key and AES for
 * symmetric encryption.
 */
public class HPKEPublicKey {
    final byte[] curve25519PublicKey;

    public HPKEPublicKey(byte[] serialized) {
        if (serialized.length != Curve25519.KEY_SIZE) {
            throw new IllegalArgumentException("Wrong key length: " + serialized.length);
        }
        this.curve25519PublicKey = serialized;
    }

    /* package */ byte[] dhExchange(HPKESecretKey other) {
        byte[] result = new byte[Curve25519.KEY_SIZE];
        Curve25519.curve(result, other.curve25519SecretKey, curve25519PublicKey);
        return result;
    }

    public byte[] encrypt(byte[] plaintext) {
        Pair<HPKEPublicKey, HPKESecretKey> ephemeralKeyPair = generateKeyPair();
        byte[] symmetricKey = dhExchange(ephemeralKeyPair.getRight());
        byte[] symmetricCiphertext = Utils.aeadEncrypt(plaintext, new byte[0], symmetricKey, true);
        return Utils.serialize(new HPKEMessage(ByteBuffer.wrap(ephemeralKeyPair.getLeft().serialize()),
                ByteBuffer.wrap(symmetricCiphertext)));
    }

    public byte[] serialize() {
        return curve25519PublicKey;
    }

    public static Pair<HPKEPublicKey, HPKESecretKey> generateKeyPair() {
        byte[] secretKey = Utils.getSecureRandomBytes(Curve25519.KEY_SIZE);
        byte[] publicKey = new byte[Curve25519.KEY_SIZE];
        Curve25519.keygen(publicKey, null, secretKey);
        return Pair.of(new HPKEPublicKey(publicKey), new HPKESecretKey(secretKey));
    }
}
