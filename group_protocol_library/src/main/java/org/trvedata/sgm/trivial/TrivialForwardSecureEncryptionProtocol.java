package org.trvedata.sgm.trivial;

import org.trvedata.sgm.ForwardSecureEncryptionProtocol;

/**
 * Trivial implementation of {@link ForwardSecureEncryptionProtocol}, which fulfills all the class's contracts but does
 * not do any cryptography.
 */
public class TrivialForwardSecureEncryptionProtocol implements
        ForwardSecureEncryptionProtocol<TrivialForwardSecureEncryptionProtocol.State> {
    @Override
    public EncryptionResult<State> encrypt(final State state, final byte[] plaintext) {
        return new EncryptionResult<>(state, plaintext);
    }

    @Override
    public DecryptionResult<State> decrypt(final State state, final byte[] ciphertext) {
        return new DecryptionResult<>(state, ciphertext);
    }

    @Override
    public State init(final Key key) {
        return new State();
    }

    public static class State implements ForwardSecureEncryptionProtocol.State {
    }
}
