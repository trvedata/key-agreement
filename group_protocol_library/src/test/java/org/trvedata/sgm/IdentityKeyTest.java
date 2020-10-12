package org.trvedata.sgm;

import org.junit.Test;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.crypto.IdentityKeyPair;

import static org.assertj.core.api.Assertions.assertThat;

public class IdentityKeyTest {
    @Test
    public void test_signedMessage_thenVerifies() {
        IdentityKeyPair identityKeyPair = IdentityKey.generateKeyPair();
        byte[] message = "test".getBytes();
        byte[] signature = identityKeyPair.sign(message);
        assertThat(identityKeyPair.getPublicKey().verify(message, signature)).isTrue();
    }

    @Test
    public void test_corruptedSignatures_thenVerificationFails() {
        IdentityKeyPair identityKeyPair = IdentityKey.generateKeyPair();
        byte[] message = "test".getBytes();
        byte[] signature = identityKeyPair.sign(message);
        assertThat(identityKeyPair.getPublicKey().verify("testOther".getBytes(), signature)).isFalse();
    }

    @Test
    public void test_equalsDeserialized() {
        IdentityKey identityKey = IdentityKey.generateKeyPair().getPublicKey();
        IdentityKey deserialized = new IdentityKey(identityKey.serialize());
        assertThat(identityKey.equals(deserialized)).isTrue();
    }
}
