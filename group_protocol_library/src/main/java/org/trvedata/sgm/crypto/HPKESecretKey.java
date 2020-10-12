package org.trvedata.sgm.crypto;

import djb.Curve25519;
import org.apache.thrift.TException;
import org.trvedata.sgm.message.HPKEMessage;
import org.trvedata.sgm.misc.Utils;

public class HPKESecretKey {
    final byte[] curve25519SecretKey;

    public HPKESecretKey(byte[] serialized) {
        if (serialized.length != Curve25519.KEY_SIZE) {
            throw new IllegalArgumentException("Wrong key length: " + serialized.length);
        }
        this.curve25519SecretKey = serialized;
    }

    /**
     * Returns null if decryption fails.
     */
    public byte[] decrypt(byte[] ciphertext) {
        HPKEMessage deserialized = new HPKEMessage();
        HPKEPublicKey ephemeralPublicKey;
        try {
            Utils.deserialize(deserialized, ciphertext);
            ephemeralPublicKey = new HPKEPublicKey(deserialized.getDhPublicKey());
        } catch (TException | IllegalArgumentException exc) {
            return null;
        }
        byte[] symmetricKey = ephemeralPublicKey.dhExchange(this);
        return Utils.aeadDecrypt(deserialized.getSymmetricCiphertext(), symmetricKey);
    }

    public byte[] serialize() {
        return curve25519SecretKey;
    }
}
