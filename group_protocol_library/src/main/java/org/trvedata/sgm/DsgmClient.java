package org.trvedata.sgm;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.trvedata.sgm.communication.Client;
import org.trvedata.sgm.communication.Network;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.crypto.IdentityKeyPair;
import org.trvedata.sgm.crypto.PreKeySecret;
import org.trvedata.sgm.crypto.PreKeySource;
import org.trvedata.sgm.misc.Logger;
import org.trvedata.sgm.trivial.TrivialDcgkaProtocol;
import org.trvedata.sgm.trivial.TrivialForwardSecureEncryptionProtocol;
import org.trvedata.sgm.trivial.TrivialOrderer;
import org.trvedata.sgm.trivial.TrivialSignatureProtocol;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * A {@link DsgmClient} is the interface to be used by an application or test environment making use of the DCGKA
 * protocol. It encapsulates the protocol state and pre shared information and brokers between these and the network.
 */
public class DsgmClient extends Client {

    private final IdentityKeyPair mIdentityKeyPair;

    private DsgmProtocol mDsgmProtocol;
    private DsgmProtocol.State mDgmProtocolState;

    private ArrayList<DsgmListener> mListeners = new ArrayList<>();

    public DsgmClient(
            final Network network,
            final PreKeySecret preKeySecret, final PreKeySource preKeySource, final String name,
            final IdentityKeyPair identityKeyPair) {
        this(network, preKeySecret, preKeySource, name, identityKeyPair, DgmClientImplementationConfiguration.full());
    }

    /**
     * Used for integration testing only, allowing a mix of trivial and full protocol components.
     */
    /* package */ DsgmClient(
            final Network network,
            final PreKeySecret preKeySecret, final PreKeySource preKeySource, final String name,
            final IdentityKeyPair identityKeyPair,
            final DgmClientImplementationConfiguration implementationConfiguration) {
        mIdentityKeyPair = identityKeyPair;

        DcgkaProtocol dcgkaProtocol;
        DcgkaProtocol.State dcgkaState;
        switch (implementationConfiguration.dcgkaChoice) {
            case TRIVIAL:
                dcgkaProtocol = new TrivialDcgkaProtocol();
                dcgkaState = new TrivialDcgkaProtocol.State(identityKeyPair.getPublicKey());
                break;
            case FULL:
                dcgkaProtocol = new FullDcgkaProtocol();
                dcgkaState = new FullDcgkaProtocol.State(identityKeyPair.getPublicKey(), preKeySecret, preKeySource);
                break;
            default:
                throw new IllegalArgumentException("Unrecognized DcgkaChoice: " + implementationConfiguration.dcgkaChoice);
        }

        ForwardSecureEncryptionProtocol forwardSecureEncryptionProtocol;
        if (implementationConfiguration.fullForwardSecureEncryptionProtocol) {
            forwardSecureEncryptionProtocol = new InOrderForwardSecureEncryptionProtocol();
        } else {
            forwardSecureEncryptionProtocol = new TrivialForwardSecureEncryptionProtocol();
        }

        Orderer orderer;
        Orderer.State ordererState;
        if (implementationConfiguration.fullOrderer) {
            orderer = new AckOrderer();
            ordererState = new AckOrderer.State<>(identityKeyPair.getPublicKey());
        } else {
            orderer = new TrivialOrderer();
            ordererState = new TrivialOrderer.State<>();
        }
        SignatureProtocol signatureProtocol;
        SignatureProtocol.State signatureState;
        if (implementationConfiguration.fullSignatureProtocol) {
            signatureProtocol = new RotatingSignatureProtocol();
            signatureState = new RotatingSignatureProtocol.State(identityKeyPair);
        } else {
            signatureProtocol = new TrivialSignatureProtocol();
            signatureState = new TrivialSignatureProtocol.State();
        }

        mDsgmProtocol = new ModularDsgm(dcgkaProtocol, forwardSecureEncryptionProtocol, orderer, signatureProtocol);
        mDgmProtocolState = new ModularDsgm.State<>(identityKeyPair.getPublicKey(), dcgkaState, ordererState, signatureState);

        init(network, name);
    }

    @Override
    public IdentityKey getIdentifier() {
        return mIdentityKeyPair.getPublicKey();
    }

    public Collection getMembers() {
        return mDsgmProtocol.getMembers(mDgmProtocolState);
    }

    /**
     * {@code} members must NOT include us.
     *
     * @param members The other group members in the group being created.
     */
    public void create(Collection<IdentityKey> members) {
        Pair<? extends DsgmProtocol.State, byte[]> result = mDsgmProtocol.create(mDgmProtocolState, members);
        mDgmProtocolState = result.getLeft();
        sendMessageToGroupMembers(result.getRight());
    }

    public void add(IdentityKey added) {
        Triple<? extends DsgmProtocol.State, byte[], byte[]> result = mDsgmProtocol.add(mDgmProtocolState, added);
        mDgmProtocolState = result.getLeft();
        sendMessageToGroupMembers(result.getRight());
        send(added, result.getMiddle());
    }

    public void remove(IdentityKey removed) {
        Pair<? extends DsgmProtocol.State, byte[]> result = mDsgmProtocol.remove(mDgmProtocolState, removed);
        mDgmProtocolState = result.getLeft();
        sendMessageToGroupMembers(result.getRight());
    }

    public void update() {
        Pair<? extends DsgmProtocol.State, byte[]> result = mDsgmProtocol.update(mDgmProtocolState);
        mDgmProtocolState = result.getLeft();
        sendMessageToGroupMembers(result.getRight());
    }

    public void send(byte[] plaintext) {
        Pair<? extends DsgmProtocol.State, byte[]> result = mDsgmProtocol.send(mDgmProtocolState, plaintext);
        mDgmProtocolState = result.getLeft();
        sendMessageToGroupMembers(result.getRight());
    }

    @Override
    public void handleMessageFromNetwork(final Object senderIdentifier, final byte[] bytes) {
        try {
            final Pair<? extends DsgmProtocol.State, List<DsgmProtocol.MessageEffect>> receiveResult =
                    mDsgmProtocol.receive(mDgmProtocolState, bytes);
            mDgmProtocolState = receiveResult.getLeft();

            for (DsgmProtocol.MessageEffect messageEffect : receiveResult.getRight()) {
                processMessageEffectToListenerCalls(messageEffect);
                if (messageEffect.responseMessage != null) {
                    sendMessageToGroupMembers(messageEffect.responseMessage);
                }
            }
        } catch (final Exception e) {
            Logger.w("DsgmClient", name + ": Failed to process incoming message due to " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * Hands the given message over to the network to broadcast.  Note that it will also be sent to
     * connected clients that are not yet in the group, which is fine as long as we use AckOrderer.
     */
    private void sendMessageToGroupMembers(final byte[] message) {
        broadcast(message);
    }

    /**
     * Takes a {@link DsgmProtocol.MessageEffect} and calls the respective methods of the currently registered {@link
     * #mListeners}.
     */
    private void processMessageEffectToListenerCalls(final DsgmProtocol.MessageEffect messageEffect) {
        for (DsgmListener mListener : mListeners) {
            if (messageEffect.type == DsgmProtocol.DgmMessageType.APPLICATION) {
                mListener.onIncomingMessage(messageEffect.sender, messageEffect.plaintext);
            }

            if (messageEffect.type == DsgmProtocol.DgmMessageType.UPDATE) {
                mListener.onUpdate(messageEffect.sender, messageEffect.messageId);
            }

            for (final IdentityKey added : messageEffect.added) {
                mListener.onAdd(messageEffect.sender, added, messageEffect.messageId);
            }

            if (!messageEffect.removed.isEmpty()) {
                final ArrayList<IdentityKey> removed = new ArrayList<>(messageEffect.removed);
                mListener.onRemove(messageEffect.sender, removed, messageEffect.messageId);
            }

            for (final Object ackedMessage : messageEffect.ackedMessageIds) {
                mListener.onAck(messageEffect.sender, ackedMessage);
            }
        }
    }

    /**
     * Adds the given listener to react on incoming payload, add, remove, and ack messages.
     */
    public <T extends DsgmListener> void addListener(final T listener) {
        mListeners.add(listener);
    }

    /**
     * The application is encouraged to set this listener using {@link #addListener(DsgmListener)} so as to get
     * feedback on the group state and message delivery.
     */
    public interface DsgmListener {
        void onIncomingMessage(IdentityKey sender, byte[] plaintext);

        void onUpdate(IdentityKey updater, Object messageId);

        void onAdd(IdentityKey adder, IdentityKey added, Object messageId);

        void onRemove(IdentityKey remover, ArrayList<IdentityKey> removed, Object messageId);

        void onAck(IdentityKey acker, Object acked);

    }

    @Override
    public String toString() {
        return "DgmClient{" + getName(getIdentifier()) + "}";
    }

    public enum DcgkaChoice {
        TRIVIAL,
        FULL
    }

    public static class DgmClientImplementationConfiguration {
        final DcgkaChoice dcgkaChoice;
        final boolean fullForwardSecureEncryptionProtocol;
        final boolean fullOrderer;
        final boolean fullSignatureProtocol;

        public DgmClientImplementationConfiguration(
                final DcgkaChoice dcgkaChoice,
                final boolean fullForwardSecureEncryptionProtocol,
                final boolean fullOrderer,
                final boolean fullSignatureProtocol) {
            this.dcgkaChoice = dcgkaChoice;
            this.fullForwardSecureEncryptionProtocol = fullForwardSecureEncryptionProtocol;
            this.fullOrderer = fullOrderer;
            this.fullSignatureProtocol = fullSignatureProtocol;
        }

        public static DgmClientImplementationConfiguration full() {
            return new DgmClientImplementationConfiguration(DcgkaChoice.FULL, true, true, true);
        }
    }

}
