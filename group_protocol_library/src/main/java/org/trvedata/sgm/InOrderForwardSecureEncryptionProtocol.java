package org.trvedata.sgm;

import org.trvedata.sgm.misc.Utils;

/**
 * Forward secure implementation of SignatureProtocol, allowing in-order message delivery only.
 */
public class InOrderForwardSecureEncryptionProtocol implements
        ForwardSecureEncryptionProtocol<InOrderForwardSecureEncryptionProtocol.State> {
    @Override
    public EncryptionResult<State> encrypt(final State state, final byte[] plaintext) {
        final byte[] newChainKey = Utils.hash("chain", state.nextChainKey);
        final byte[] ciphertext = Utils.aeadEncrypt(plaintext, new byte[0], state.nextChainKey, true);
        return new EncryptionResult<>(new State(newChainKey), ciphertext);
    }

    @Override
    public DecryptionResult<State> decrypt(final State state, final byte[] ciphertext) {
        final byte[] newChainKey = Utils.hash("chain", state.nextChainKey);
        final byte[] plaintext = Utils.aeadDecrypt(ciphertext, state.nextChainKey);
        return new DecryptionResult<>(new State(newChainKey), plaintext);
    }

    @Override
    public State init(final Key key) {
        return new State(key.getBytes());
    }

    public static class State implements ForwardSecureEncryptionProtocol.State {
        final byte[] nextChainKey;

        private State(final byte[] nextChainKey) {
            this.nextChainKey = nextChainKey;
        }
    }
}
