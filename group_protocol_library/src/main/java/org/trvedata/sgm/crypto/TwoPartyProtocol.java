package org.trvedata.sgm.crypto;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.thrift.TException;
import org.pcollections.HashPMap;
import org.pcollections.HashTreePMap;
import org.trvedata.sgm.message.TwoPartyMessage;
import org.trvedata.sgm.message.TwoPartyPlaintext;
import org.trvedata.sgm.misc.Utils;

import java.nio.ByteBuffer;


/**
 * Persistent implementation of the 2SM scheme from our paper.
 */
public class TwoPartyProtocol {
    private final PreKeySecret preKeySecret;
    private final PreKeySource preKeySource;
    private final IdentityKey peer;
    private final HashPMap<Integer, HPKESecretKey> mySks;
    // minIndex is the minimum index present in mySks, or nextIndex if there are no keys present
    private final int minIndex, nextIndex;
    private final HPKEPublicKey otherPk;
    private final boolean amIOtherPkSender;
    private final int otherPkIndex;
    private final HPKESecretKey receivedSk;

    /**
     * Initialize a protocol instance, using the given {@code SessionCipher} for
     * the initial message(s) involving prekeys.
     */
    public TwoPartyProtocol(PreKeySecret preKeySecret, PreKeySource preKeySource, IdentityKey peer) {
        this(preKeySecret, preKeySource, peer, HashTreePMap.empty(), 1, 1, null, false, 0, null);
    }

    private TwoPartyProtocol(PreKeySecret preKeySecret, PreKeySource preKeySource, IdentityKey peer,
                             HashPMap<Integer, HPKESecretKey> mySks,
                             int minIndex, int nextIndex, HPKEPublicKey otherPk, boolean amIOtherPkSender,
                             int otherPkIndex, HPKESecretKey receivedSk) {
        this.preKeySecret = preKeySecret;
        this.preKeySource = preKeySource;
        this.peer = peer;
        this.mySks = mySks;
        this.minIndex = minIndex;
        this.nextIndex = nextIndex;
        this.otherPk = otherPk;
        this.amIOtherPkSender = amIOtherPkSender;
        this.otherPkIndex = otherPkIndex;
        this.receivedSk = receivedSk;
    }

    /**
     * Returns the encryption of plaintext.
     */
    public Pair<TwoPartyProtocol, byte[]> encrypt(byte[] plaintext) {
        Pair<HPKEPublicKey, HPKESecretKey> myNewKeyPair = HPKEPublicKey.generateKeyPair();
        Pair<HPKEPublicKey, HPKESecretKey> otherNewKeyPair = HPKEPublicKey.generateKeyPair();
        byte[] twoPartyPlaintext = Utils.serialize(new TwoPartyPlaintext(
                ByteBuffer.wrap(plaintext), ByteBuffer.wrap(otherNewKeyPair.getRight().serialize()),
                this.nextIndex, ByteBuffer.wrap(myNewKeyPair.getLeft().serialize())));
        byte[] ciphertext;
        if (this.otherPk == null) {
            // We don't yet have an HPKE public key for other; use prekeys.
            ciphertext = this.preKeySecret.encrypt(twoPartyPlaintext, this.preKeySource.getPreKey(this.peer));
        } else ciphertext = this.otherPk.encrypt(twoPartyPlaintext);
        TwoPartyMessage message = new TwoPartyMessage(ByteBuffer.wrap(ciphertext),
                this.amIOtherPkSender, this.otherPkIndex);
        return Pair.of(new TwoPartyProtocol(this.preKeySecret, this.preKeySource, this.peer,
                        this.mySks.plus(this.nextIndex, myNewKeyPair.getRight()), this.minIndex,
                        this.nextIndex + 1, otherNewKeyPair.getLeft(), true,
                        -1, this.receivedSk),
                Utils.serialize(message));
    }

    /**
     * If ciphertext can be properly decrypted, returns the p used
     * to generate it.  Otherwise returns null.
     */
    public Pair<TwoPartyProtocol, byte[]> decrypt(byte[] ciphertext) {
        TwoPartyMessage message = new TwoPartyMessage();
        try {
            Utils.deserialize(message, ciphertext);
        } catch (TException e) {
            return null;
        }
        byte[] plaintext;
        HashPMap<Integer, HPKESecretKey> newMySks = this.mySks;
        int newMinIndex = this.minIndex;
        if (message.isSenderOtherPkSender()) {
            // Decrypt with the last key given to us by other
            if (this.receivedSk == null) return null;
            plaintext = this.receivedSk.decrypt(message.getCiphertext());
            if (plaintext == null) return null;
        } else {
            if (message.getReceiverPkIndex() == 0) {
                // Our public key with index 0 is our prekey.
                Pair<PreKeySecret, byte[]> result = this.preKeySecret.decrypt(message.getCiphertext(), this.peer);
                if (result == null) return null;
                plaintext = result.getRight();
                if (plaintext == null) return null;
            } else {
                // Use our secret key with the given index
                HPKESecretKey secretKey = this.mySks.get(message.getReceiverPkIndex());
                if (secretKey == null) return null;
                plaintext = secretKey.decrypt(message.getCiphertext());
                if (plaintext == null) return null;
                // Delete this key and older ones from this.mySks
                for (int i = this.minIndex; i <= message.getReceiverPkIndex(); i++) {
                    newMySks = newMySks.minus(i);
                }
                newMinIndex = message.getReceiverPkIndex() + 1;
            }
        }
        TwoPartyPlaintext twoPartyPlaintext = new TwoPartyPlaintext();
        try {
            Utils.deserialize(twoPartyPlaintext, plaintext);
        } catch (TException exc) {
            return null;
        }
        return Pair.of(new TwoPartyProtocol(null, null, null, newMySks, newMinIndex, this.nextIndex,
                        new HPKEPublicKey(twoPartyPlaintext.getSenderNewPk()), false,
                        twoPartyPlaintext.getSenderNewPkIndex(),
                        new HPKESecretKey(twoPartyPlaintext.getReceiverNewSk())),
                twoPartyPlaintext.getAppPlaintext());
    }
}
