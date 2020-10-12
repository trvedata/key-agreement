package org.trvedata.sgm;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class InOrderForwardSecureEncryptionProtocolTest {

    @Test
    public void test_whenEncryptedWithState_thenSameStateDecrypts_thenNewStateDoesNotDecrypt() {
        final InOrderForwardSecureEncryptionProtocol protocol = new InOrderForwardSecureEncryptionProtocol();
        final InOrderForwardSecureEncryptionProtocol.State state0 = protocol.init(ForwardSecureEncryptionProtocol.Key.random());

        final byte[] plaintext = "plaintext".getBytes();
        final ForwardSecureEncryptionProtocol.EncryptionResult<InOrderForwardSecureEncryptionProtocol.State> encryptionResult = protocol.encrypt(state0, plaintext);

        final ForwardSecureEncryptionProtocol.DecryptionResult<InOrderForwardSecureEncryptionProtocol.State> decryptionResult0 = protocol.decrypt(state0, encryptionResult.ciphertext);
        assertThat(plaintext).isEqualTo(decryptionResult0.plaintext);

        final ForwardSecureEncryptionProtocol.DecryptionResult<InOrderForwardSecureEncryptionProtocol.State> decryptionResult1 = protocol.decrypt(encryptionResult.state, encryptionResult.ciphertext);
        assertThat(plaintext).isNotEqualTo(decryptionResult1.plaintext);
    }

    @Test
    public void test_whenEncryptedWithSameState_thenSameResult() {
        final InOrderForwardSecureEncryptionProtocol protocol = new InOrderForwardSecureEncryptionProtocol();
        final InOrderForwardSecureEncryptionProtocol.State state0 = protocol.init(ForwardSecureEncryptionProtocol.Key.random());

        final byte[] plaintext = "plaintext".getBytes();
        final ForwardSecureEncryptionProtocol.EncryptionResult<InOrderForwardSecureEncryptionProtocol.State> encryptionResultA = protocol.encrypt(state0, plaintext);
        final ForwardSecureEncryptionProtocol.EncryptionResult<InOrderForwardSecureEncryptionProtocol.State> encryptionResultB = protocol.encrypt(state0, plaintext);

        assertThat(encryptionResultA.ciphertext).isEqualTo(encryptionResultB.ciphertext);
    }

    @Test
    public void test_whenEncryptedWithState_thenRandomStateDoesNotDecrypt() {
        final InOrderForwardSecureEncryptionProtocol protocol = new InOrderForwardSecureEncryptionProtocol();
        final InOrderForwardSecureEncryptionProtocol.State state0 = protocol.init(ForwardSecureEncryptionProtocol.Key.random());
        final InOrderForwardSecureEncryptionProtocol.State state1 = protocol.init(ForwardSecureEncryptionProtocol.Key.random());

        final byte[] plaintext = "plaintext".getBytes();
        final ForwardSecureEncryptionProtocol.EncryptionResult<InOrderForwardSecureEncryptionProtocol.State> encryptionResult = protocol.encrypt(state0, plaintext);
        final ForwardSecureEncryptionProtocol.DecryptionResult<InOrderForwardSecureEncryptionProtocol.State> decryptionResult = protocol.decrypt(state1, encryptionResult.ciphertext);

        assertThat(plaintext).isNotEqualTo(decryptionResult.plaintext);
    }

    @Test
    public void test_whenEncryptedAndNewState_thenDecryptionFollowsState() {
        final InOrderForwardSecureEncryptionProtocol protocol = new InOrderForwardSecureEncryptionProtocol();
        final InOrderForwardSecureEncryptionProtocol.State initialState = protocol.init(ForwardSecureEncryptionProtocol.Key.random());

        final byte[] plaintext = "plaintext".getBytes();
        final ForwardSecureEncryptionProtocol.EncryptionResult<InOrderForwardSecureEncryptionProtocol.State> encryptionResultA = protocol.encrypt(initialState, plaintext);
        final ForwardSecureEncryptionProtocol.EncryptionResult<InOrderForwardSecureEncryptionProtocol.State> encryptionResultB = protocol.encrypt(encryptionResultA.state, plaintext);

        final ForwardSecureEncryptionProtocol.DecryptionResult<InOrderForwardSecureEncryptionProtocol.State> decryptionResultA = protocol.decrypt(initialState, encryptionResultA.ciphertext);
        final ForwardSecureEncryptionProtocol.DecryptionResult<InOrderForwardSecureEncryptionProtocol.State> decryptionResultB = protocol.decrypt(decryptionResultA.state, encryptionResultB.ciphertext);

        assertThat(plaintext).isEqualTo(decryptionResultA.plaintext);
        assertThat(plaintext).isEqualTo(decryptionResultB.plaintext);
    }
}
