package org.trvedata.sgm.trivial;

import org.apache.commons.lang3.tuple.Pair;
import org.trvedata.sgm.SignatureProtocol;
import org.trvedata.sgm.crypto.IdentityKey;

/**
 * Trivial implementation of {@link SignatureProtocol}, which fulfills all the class's contracts but does
 * not do any cryptography.
 */
public class TrivialSignatureProtocol implements SignatureProtocol<TrivialSignatureProtocol.State> {
    @Override
    public Signature getSignature(State state, byte[] message) {
        return Signature.of(new byte[0]);
    }

    @Override
    public boolean verify(State state, boolean isWelcome, byte[] message, IdentityKey sender, Signature signature) {
        return true;
    }

    @Override
    public Pair<State, Update> update(State state) {
        return Pair.of(state, Update.of(new byte[0]));
    }

    @Override
    public State processUpdate(State state, Update update, IdentityKey sender) {
        return state;
    }

    @Override
    public Update getWelcomeInfo(State state) {
        return Update.of(new byte[0]);
    }

    @Override
    public State processWelcomeInfo(State state, Update welcomeInfo, IdentityKey sender) {
        return state;
    }

    @Override
    public Signature getWelcomeSignature(State state, byte[] message) {
        return Signature.of(new byte[0]);
    }

    public static class State implements SignatureProtocol.State {
    }
}
