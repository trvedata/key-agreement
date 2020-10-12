package org.trvedata.sgm;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Test;
import org.trvedata.sgm.crypto.*;

import static org.assertj.core.api.Assertions.assertThat;

public class TwoPartyProtocolTest {

    @Test
    public void test_unidirectionalMessages_thenDecryptsCorrectly() {
        final Pair<TwoPartyProtocol, TwoPartyProtocol> protocols = initialize();
        TwoPartyProtocol alice = protocols.getLeft();
        TwoPartyProtocol bob = protocols.getRight();

        for (int i = 0; i < 10; i++) {
            byte[] plaintext = ("plaintext" + i).getBytes();
            Pair<TwoPartyProtocol, byte[]> encryptionResult = alice.encrypt(plaintext);
            alice = encryptionResult.getLeft();
            Pair<TwoPartyProtocol, byte[]> decryptionResult = bob.decrypt(encryptionResult.getRight());
            bob = decryptionResult.getLeft();
            assertThat(plaintext).isEqualTo(decryptionResult.getRight());
        }
    }

    @Test
    public void test_strictAlternation_thenDecryptsCorrectly() {
        final Pair<TwoPartyProtocol, TwoPartyProtocol> protocols = initialize();
        TwoPartyProtocol alice = protocols.getLeft();
        TwoPartyProtocol bob = protocols.getRight();

        for (int i = 0; i < 10; i++) {
            byte[] plaintextAlice = ("plaintextAlice" + i).getBytes();
            Pair<TwoPartyProtocol, byte[]> encryptionResult1 = alice.encrypt(plaintextAlice);
            alice = encryptionResult1.getLeft();
            Pair<TwoPartyProtocol, byte[]> decryptionResult1 = bob.decrypt(encryptionResult1.getRight());
            bob = decryptionResult1.getLeft();
            assertThat(plaintextAlice).isEqualTo(decryptionResult1.getRight());

            byte[] plaintextBob = ("plaintextBob" + i).getBytes();
            Pair<TwoPartyProtocol, byte[]> encryptionResult2 = bob.encrypt(plaintextBob);
            bob = encryptionResult2.getLeft();
            Pair<TwoPartyProtocol, byte[]> decryptionResult2 = alice.decrypt(encryptionResult2.getRight());
            alice = decryptionResult2.getLeft();
            assertThat(plaintextBob).isEqualTo(decryptionResult2.getRight());
        }
    }

    @Test
    public void test_lockStepConcurrentMessages_thenDecryptsCorrecty() {
        final Pair<TwoPartyProtocol, TwoPartyProtocol> protocols = initialize();
        TwoPartyProtocol alice = protocols.getLeft();
        TwoPartyProtocol bob = protocols.getRight();

        for (int i = 0; i < 10; i++) {
            byte[] plaintextAlice = ("plaintextAlice" + i).getBytes();
            Pair<TwoPartyProtocol, byte[]> encryptionResult1 = alice.encrypt(plaintextAlice);
            alice = encryptionResult1.getLeft();

            byte[] plaintextBob = ("plaintextBob" + i).getBytes();
            Pair<TwoPartyProtocol, byte[]> encryptionResult2 = bob.encrypt(plaintextBob);
            bob = encryptionResult2.getLeft();

            Pair<TwoPartyProtocol, byte[]> decryptionResult1 = bob.decrypt(encryptionResult1.getRight());
            bob = decryptionResult1.getLeft();
            assertThat(plaintextAlice).isEqualTo(decryptionResult1.getRight());

            Pair<TwoPartyProtocol, byte[]> decryptionResult2 = alice.decrypt(encryptionResult2.getRight());
            alice = decryptionResult2.getLeft();
            assertThat(plaintextBob).isEqualTo(decryptionResult2.getRight());
        }
    }

    @Test
    public void test_whenEncryptedWithState_thenSameStateDecrypts_thenNewStateDoesNotDecrypt() {
        final Pair<TwoPartyProtocol, TwoPartyProtocol> protocols = initialize();
        TwoPartyProtocol alice = protocols.getLeft();
        TwoPartyProtocol bob = protocols.getRight();

        final byte[] plaintext1 = "plaintext1".getBytes();
        final Pair<TwoPartyProtocol, byte[]> encryptionResult1 = alice.encrypt(plaintext1);
        alice = encryptionResult1.getLeft();
        final Pair<TwoPartyProtocol, byte[]> decryptionResult1 = bob.decrypt(encryptionResult1.getRight());
        bob = decryptionResult1.getLeft();
        assertThat(plaintext1).isEqualTo(decryptionResult1.getRight());

        final byte[] plaintext2 = "plaintext2".getBytes();
        final Pair<TwoPartyProtocol, byte[]> encryptionResult2 = alice.encrypt(plaintext2);
        final Pair<TwoPartyProtocol, byte[]> decryptionResult2 = bob.decrypt(encryptionResult2.getRight());
        assertThat(plaintext2).isEqualTo(decryptionResult2.getRight());
        assertThat(decryptionResult2.getLeft().decrypt(encryptionResult2.getRight())).isNull();
    }

    private Pair<TwoPartyProtocol, TwoPartyProtocol> initialize() {
        InMemoryPreKeySource preKeySource = new InMemoryPreKeySource();
        IdentityKeyPair aliceKeyPair = IdentityKey.generateKeyPair();
        PreKeySecret alicePreKeySecret = preKeySource.registerUser(aliceKeyPair, 1);
        IdentityKeyPair bobKeyPair = IdentityKey.generateKeyPair();
        PreKeySecret bobPreKeySecret = preKeySource.registerUser(bobKeyPair, 1);
        return Pair.of(new TwoPartyProtocol(alicePreKeySecret, preKeySource, bobKeyPair.getPublicKey()),
                new TwoPartyProtocol(bobPreKeySecret, preKeySource, aliceKeyPair.getPublicKey()));
    }
}
