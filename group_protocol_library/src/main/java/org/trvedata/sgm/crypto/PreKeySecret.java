package org.trvedata.sgm.crypto;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.thrift.TException;
import org.pcollections.HashPMap;
import org.pcollections.HashTreePMap;
import org.trvedata.sgm.message.PreKeyCiphertext;
import org.trvedata.sgm.misc.Utils;

import java.nio.ByteBuffer;

public class PreKeySecret {
    private final IdentityKeyPair identityKeyPair;
    private final HPKEPublicKey signedPreKey;
    private final HPKESecretKey signedPreKeySecret;
    private final byte[] signedPreKeySig;
    private final HashPMap<Integer, HPKESecretKey> oneTimeKeySecrets;
    private final int nextId;

    public PreKeySecret(IdentityKeyPair identityKeyPair) {
        this.identityKeyPair = identityKeyPair;
        Pair<HPKEPublicKey, HPKESecretKey> signedPair = HPKEPublicKey.generateKeyPair();
        this.signedPreKey = signedPair.getLeft();
        this.signedPreKeySecret = signedPair.getRight();
        this.signedPreKeySig = this.identityKeyPair.sign(this.signedPreKey.serialize());
        this.oneTimeKeySecrets = HashTreePMap.empty();
        this.nextId = 0;
    }

    private PreKeySecret(PreKeySecret old, HashPMap<Integer, HPKESecretKey> oneTimeKeySecrets, int nextId) {
        this.identityKeyPair = old.identityKeyPair;
        this.signedPreKey = old.signedPreKey;
        this.signedPreKeySecret = old.signedPreKeySecret;
        this.signedPreKeySig = old.signedPreKeySig;
        this.oneTimeKeySecrets = oneTimeKeySecrets;
        this.nextId = nextId;
    }

    public Pair<PreKeySecret, PreKey> generatePreKey() {
        Pair<HPKEPublicKey, HPKESecretKey> oneTimePair = HPKEPublicKey.generateKeyPair();
        return Pair.of(
                new PreKeySecret(this, this.oneTimeKeySecrets.plus(this.nextId, oneTimePair.getRight()), this.nextId + 1),
                new PreKey(this.identityKeyPair.publicKey, this.signedPreKey, this.signedPreKeySig,
                        oneTimePair.getLeft(), this.nextId)
        );
    }

    public byte[] encrypt(byte[] plaintext, PreKey recipientPreKey) {
        // Uses X3DH as specified in
        // https://www.signal.org/docs/specifications/x3dh/#the-x3dh-protocol
        if (!recipientPreKey.identityKey.verify(recipientPreKey.signedPreKey.serialize(), recipientPreKey.signedPreKeySig)) {
            throw new IllegalArgumentException("Signed prekey verification failed");
        }
        Pair<HPKEPublicKey, HPKESecretKey> ephemeralKeyPair = HPKEPublicKey.generateKeyPair();
        byte[] dh1 = recipientPreKey.signedPreKey.dhExchange(this.identityKeyPair.asHpkeSecretKey());
        byte[] dh2 = recipientPreKey.identityKey.asHpkeKey().dhExchange(ephemeralKeyPair.getRight());
        byte[] dh3 = recipientPreKey.signedPreKey.dhExchange(ephemeralKeyPair.getRight());
        byte[] dh4 = recipientPreKey.oneTimeKey.dhExchange(ephemeralKeyPair.getRight());
        byte[] sk = Utils.hash(dh1, dh2, dh3, dh4);
        byte[] ad = Utils.concat(this.identityKeyPair.publicKey.serialize(), recipientPreKey.identityKey.serialize());
        return Utils.serialize(new PreKeyCiphertext(
                ByteBuffer.wrap(ephemeralKeyPair.getLeft().serialize()),
                recipientPreKey.id,
                ByteBuffer.wrap(Utils.aeadEncrypt(plaintext, ad, sk, false))
        ));
    }

    public Pair<PreKeySecret, byte[]> decrypt(byte[] ciphertext, IdentityKey sender) {
        // Uses X3DH as specified in
        // https://www.signal.org/docs/specifications/x3dh/#the-x3dh-protocol
        try {
            PreKeyCiphertext deserialized = new PreKeyCiphertext();
            Utils.deserialize(deserialized, ciphertext);
            HPKEPublicKey ephemeralPublicKey = new HPKEPublicKey(deserialized.getEphemeralKey());
            HPKESecretKey oneTimeKey = this.oneTimeKeySecrets.get(deserialized.getPreKeyId());
            if (oneTimeKey == null) return null;
            byte[] dh1 = sender.asHpkeKey().dhExchange(this.signedPreKeySecret);
            byte[] dh2 = ephemeralPublicKey.dhExchange(this.identityKeyPair.asHpkeSecretKey());
            byte[] dh3 = ephemeralPublicKey.dhExchange(this.signedPreKeySecret);
            byte[] dh4 = ephemeralPublicKey.dhExchange(oneTimeKey);
            byte[] sk = Utils.hash(dh1, dh2, dh3, dh4);
            byte[] ad = Utils.concat(sender.serialize(), this.identityKeyPair.publicKey.serialize());
            byte[] plaintext = Utils.aeadDecrypt(deserialized.getCiphertext(), sk, ad);
            if (plaintext != null) {
                return Pair.of(
                        new PreKeySecret(this, this.oneTimeKeySecrets.minus(deserialized.getPreKeyId()), this.nextId),
                        plaintext
                );
            } else return null;
        } catch (TException | IllegalArgumentException exc) {
            return null;
        }
    }
}
