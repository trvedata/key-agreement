package org.trvedata.sgm;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.thrift.TException;
import org.pcollections.HashPMap;
import org.pcollections.HashTreePMap;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.crypto.IdentityKeyPair;
import org.trvedata.sgm.message.SignatureWelcomeMessage;
import org.trvedata.sgm.misc.Utils;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

/**
 * Post-compromise-secure implementation of SignatureProtocol.
 */
public class RotatingSignatureProtocol implements SignatureProtocol<RotatingSignatureProtocol.State> {
    @Override
    public Signature getSignature(State state, byte[] message) {
        try {
            return Signature.of(state.currentPrivateKey.sign(message));
        } catch (IllegalArgumentException exc) {
            throw new IllegalStateException("InvalidKeyException in getSignature", exc);
        }
    }

    @Override
    public boolean verify(State state, boolean isWelcome, byte[] message, IdentityKey sender, Signature signature) {
        try {
            if (isWelcome) {
                return sender.verify(message, signature.getBytes());
            } else {
                IdentityKey signingKey = state.currentSigningKeys.get(sender);
                if (signingKey == null) {
                    // sender has never updated their signature
                    signingKey = sender;
                }
                return signingKey.verify(message, signature.getBytes());
            }
        } catch (IllegalArgumentException exc) {
            throw new IllegalStateException("InvalidKeyException in verify for sender " + sender.hashCode(), exc);
        }
    }

    @Override
    public Pair<State, Update> update(State state) {
        // Make a random new signing key
        IdentityKeyPair newSigningPair = IdentityKey.generateKeyPair();
        return Pair.of(update(state, newSigningPair, null),
                Update.of(newSigningPair.getPublicKey().serialize()));
    }

    @Override
    public State processUpdate(State state, Update update, IdentityKey sender) {
        try {
            HashMap<IdentityKey, IdentityKey> newPublicKeys = new HashMap<>();
            newPublicKeys.put(sender, new IdentityKey(update.getBytes()));
            return update(state, null, newPublicKeys);
        } catch (IllegalArgumentException exc) {
            throw new IllegalArgumentException("InvalidKeyException while deserializing update for sender " +
                    sender.hashCode(), exc);
        }
    }

    @Override
    public Update getWelcomeInfo(State state) {
        HashMap<ByteBuffer, ByteBuffer> currentPublicKeys = new HashMap<>();
        for (Map.Entry<IdentityKey, IdentityKey> entry : state.currentSigningKeys.entrySet()) {
            currentPublicKeys.put(ByteBuffer.wrap(entry.getKey().serialize()),
                    ByteBuffer.wrap(entry.getValue().serialize()));
        }
        return Update.of(Utils.serialize(new SignatureWelcomeMessage(currentPublicKeys)));
    }

    @Override
    public State processWelcomeInfo(State state, Update welcomeInfo, IdentityKey sender) {
        if (welcomeInfo.getBytes() == null) return state;
        try {
            SignatureWelcomeMessage deserialized = new SignatureWelcomeMessage();
            Utils.deserialize(deserialized, welcomeInfo.getBytes());
            HashMap<IdentityKey, IdentityKey> newPublicKeys = new HashMap<>();
            for (Map.Entry<ByteBuffer, ByteBuffer> entry : deserialized.getCurrentPublicKeys().entrySet()) {
                IdentityKey id = new IdentityKey(Utils.asArray(entry.getKey()));
                if (id.equals(state.idPair.getPublicKey())) {
                    throw new IllegalArgumentException("Welcome attempts to set our own signing key");
                }
                newPublicKeys.put(id, new IdentityKey(Utils.asArray(entry.getValue())));
            }
            return update(state, null, newPublicKeys);
        } catch (TException | IllegalArgumentException exc) {
            throw new IllegalArgumentException("Failed to deserialize welcomeInfo", exc);
        }
    }

    @Override
    public Signature getWelcomeSignature(State state, byte[] message) {
        try {
            return Signature.of(state.idPair.sign(message));
        } catch (IllegalArgumentException exc) {
            throw new IllegalStateException("InvalidKeyException in getWelcomeSignature", exc);
        }
    }

    private State update(State state, IdentityKeyPair newSigningPair,
                         HashMap<IdentityKey, IdentityKey> extraSigningKeys) {
        IdentityKeyPair newPrivateKey = state.currentPrivateKey;
        HashPMap<IdentityKey, IdentityKey> newSigningKeys = state.currentSigningKeys;
        if (newSigningPair != null) {
            newPrivateKey = newSigningPair;
            newSigningKeys = newSigningKeys.plus(state.idPair.getPublicKey(), newSigningPair.getPublicKey());
        }
        if (extraSigningKeys != null) {
            newSigningKeys = newSigningKeys.plusAll(extraSigningKeys);
        }
        return new State(state.idPair, newPrivateKey, newSigningKeys);
    }

    public static class State implements SignatureProtocol.State {
        private final IdentityKeyPair idPair;
        private final IdentityKeyPair currentPrivateKey;
        private final HashPMap<IdentityKey, IdentityKey> currentSigningKeys;

        private State(final IdentityKeyPair idPair, final IdentityKeyPair currentPrivateKey,
                      final HashPMap<IdentityKey, IdentityKey> currentSigningKeys) {
            this.idPair = idPair;
            this.currentPrivateKey = currentPrivateKey;
            this.currentSigningKeys = currentSigningKeys;
        }

        public State(final IdentityKeyPair idPair) {
            this.idPair = idPair;
            this.currentPrivateKey = idPair;
            HashPMap<IdentityKey, IdentityKey> signingKeys = HashTreePMap.empty();
            this.currentSigningKeys = signingKeys.plus(idPair.getPublicKey(), idPair.getPublicKey());
        }
    }
}
