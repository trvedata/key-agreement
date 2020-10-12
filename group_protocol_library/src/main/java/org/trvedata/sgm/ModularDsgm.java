package org.trvedata.sgm;

import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.pcollections.HashPMap;
import org.pcollections.HashTreePMap;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.message.ModularMessage;
import org.trvedata.sgm.message.SignedMessage;
import org.trvedata.sgm.misc.Logger;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Assembles a {@link DsgmProtocol} out of modular components.
 * <p>
 * Future TODO: in a real implementation, we would need to add group ids, so that one user can multiplex between
 * different groups, and to prevent cross-group attacks (?).
 *
 * @param <T> The type of timestamps used by the {@link Orderer} and {@link DcgkaProtocol}.
 * @param <I> The type of info used by the {@link Orderer} and {@link DcgkaProtocol}.
 */
public class ModularDsgm<T, I,
        DcgkaState extends DcgkaProtocol.State,
        ForwardSecureEncryptionState extends ForwardSecureEncryptionProtocol.State,
        OrdererState extends Orderer.State,
        SignatureState extends SignatureProtocol.State>
        implements DsgmProtocol<ModularDsgm.State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState>> {
    private final DcgkaProtocol<T, I, DcgkaState> dcgkaProtocol;
    private final ForwardSecureEncryptionProtocol<ForwardSecureEncryptionState> forwardSecureEncryptionProtocol;
    private final Orderer<Pair<ModularMessage, SignedMessage>, T, I, OrdererState> orderer;
    private final SignatureProtocol<SignatureState> signatureProtocol;

    public ModularDsgm(DcgkaProtocol<T, I, DcgkaState> dcgkaProtocol,
                       ForwardSecureEncryptionProtocol<ForwardSecureEncryptionState> forwardSecureEncryptionProtocol,
                       Orderer<Pair<ModularMessage, SignedMessage>, T, I, OrdererState> orderer,
                       SignatureProtocol<SignatureState> signatureProtocol) {
        this.dcgkaProtocol = dcgkaProtocol;
        this.forwardSecureEncryptionProtocol = forwardSecureEncryptionProtocol;
        this.orderer = orderer;
        this.signatureProtocol = signatureProtocol;
    }

    @Override
    public Pair<State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState>, byte[]> create(
            State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState> state,
            Collection<IdentityKey> members) {
        Pair<DcgkaState, DcgkaProtocol.ControlMessage> dcgkaWelcome = dcgkaProtocol.create(state.dcgkaState, members);
        state = state.setDcgkaState(dcgkaWelcome.getLeft());
        ModularMessage welcome = new ModularMessage(true, true, dcgkaWelcome.getRight().getBytes(),
                Orderer.OrderInfo.of(null));
        Pair<State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState>, MessageEffect> result;
        result = process(state, welcome, null, state.id, null);
        state = result.getLeft();
        ModularMessage.Serialized welcomeSerialized = welcome.serialize();
        // Here we don't need to sign with the updated state result.getLeft() because processing our welcome won't
        // change the signatureState, and besides, welcome signatures shouldn't be subject to updates.
        SignedMessage signed = new SignedMessage(welcomeSerialized, state.id,
                signatureProtocol.getWelcomeSignature(state.signatureState, welcomeSerialized.getBytes()));
        return Pair.of(state, signed.serialize());
    }

    @Override
    public Triple<State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState>, byte[], byte[]> add(
            State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState> state,
            IdentityKey added) {
        if (getMembers(state).contains(added)) {
            throw new IllegalArgumentException("add called for existing member " + added);
        }
        Triple<DcgkaState, DcgkaProtocol.ControlMessage, DcgkaProtocol.ControlMessage> dcgkaMessages =
                dcgkaProtocol.add(state.dcgkaState, added);
        state = state.setDcgkaState(dcgkaMessages.getLeft());
        Pair<State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState>, byte[]> add =
                wrapAndProcess(state, dcgkaMessages.getRight().getBytes(), true, true);
        state = add.getLeft();
        ModularMessage welcome = new ModularMessage(true, true, dcgkaMessages.getMiddle().getBytes(),
                orderer.getWelcomeInfo(state.ordererState));
        welcome.signatureUpdate = signatureProtocol.getWelcomeInfo(state.signatureState);
        ModularMessage.Serialized welcomeSerialized = welcome.serialize();
        SignedMessage signedWelcome = new SignedMessage(welcomeSerialized, state.id,
                signatureProtocol.getWelcomeSignature(state.signatureState, welcomeSerialized.getBytes()));
        return Triple.of(state, signedWelcome.serialize(), add.getRight());
    }

    @Override
    public Pair<State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState>, byte[]> remove(
            State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState> state,
            IdentityKey removed) {
        if (!getMembers(state).contains(removed)) {
            throw new IllegalArgumentException("remove called for non-member " + removed);
        }
        if (removed.equals(state.id)) {
            throw new NotImplementedException("Don't yet support removing ourselves");
        }
        Pair<DcgkaState, DcgkaProtocol.ControlMessage> dcgkaRemove = dcgkaProtocol.remove(state.dcgkaState, removed);
        state = state.setDcgkaState(dcgkaRemove.getLeft());
        return wrapAndProcess(state, dcgkaRemove.getRight().getBytes(), true, true);
    }

    @Override
    public Pair<State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState>, byte[]> update(
            State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState> state) {
        Pair<DcgkaState, DcgkaProtocol.ControlMessage> dcgkaUpdate = dcgkaProtocol.update(state.dcgkaState);
        state = state.setDcgkaState(dcgkaUpdate.getLeft());
        return wrapAndProcess(state, dcgkaUpdate.getRight().getBytes(), true, true);
    }

    @Override
    public Pair<State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState>, byte[]> send(
            State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState> state,
            byte[] plaintext) {
        ForwardSecureEncryptionState forwardSecureEncryptionState = state.forwardSecureEncryptionStates.get(state.id);
        ForwardSecureEncryptionProtocol.EncryptionResult<ForwardSecureEncryptionState> encrypted = forwardSecureEncryptionProtocol.encrypt(
                forwardSecureEncryptionState, plaintext);
        state = state.putForwardSecureEncryptionProtocol(state.id, encrypted.state);
        return wrapAndProcess(state, encrypted.ciphertext, false, false);
    }

    @Override
    public Pair<State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState>, List<MessageEffect>> receive(
            State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState> state,
            byte[] message) {
        SignedMessage signed;
        ArrayList<MessageEffect> list = new ArrayList<>();
        try {
            signed = new SignedMessage(message);
        } catch (IllegalArgumentException exc) {
            Logger.i("ModularDsgm", state.id.hashCode() +
                    ": Failed to deserialize SignedMessage: " + exc.getMessage());
            return Pair.of(state, list);
        }
        ModularMessage modular;
        try {
            modular = new ModularMessage(signed.content);
        } catch (IllegalArgumentException exc) {
            Logger.i("ModularDsgm", state.id.hashCode() +
                    ": Failed to deserialize ModularMessage: " + exc.getMessage());
            return Pair.of(state, list);
        }
        if (modular.isWelcome) {
            // Process immediately (welcome is first message to process)
            Pair<State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState>, MessageEffect> result =
                    process(state, modular, signed, signed.sender, null);
            if (result == null) return Pair.of(state, list);
            else {
                list.add(result.getRight());
                state = result.getLeft();
            }
        } else {
            // Queue until the Orderer says it's ready
            OrdererState newOrderer = orderer.queue(state.ordererState, Pair.of(modular, signed), signed.sender,
                    modular.orderInfo);
            state = state.setOrdererState(newOrderer);
        }

        if (state.isWelcomed) {
            // Process all ready messages
            Orderer.ReadyMessage<Pair<ModularMessage, SignedMessage>, T, OrdererState> readyMessage;
            while ((readyMessage = orderer.getReadyMessage(state.ordererState)) != null) {
                Pair<State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState>, MessageEffect> result =
                        process(state.setOrdererState(readyMessage.nextState), readyMessage.message.getLeft(),
                                readyMessage.message.getRight(), readyMessage.sender, readyMessage.causalInfo);
                if (result == null) {
                    // Message is invalid, skip it.
                    // Here we purposely use the old state, not state.setOrdererState(readyMessage.nextState).
                    state = state.setOrdererState(orderer.skipReadyMessage(state.ordererState));
                } else if (result.getRight().removed.contains(state.id)) {
                    // The message removed us.  We still return its MessageEffect to alert the user, but we
                    // haven't really processed it (and we don't want to process causally later messages),
                    // so we tell Orderer to skip the message.
                    state = state.setOrdererState(orderer.skipReadyMessage(state.ordererState));
                    list.add(result.getRight());
                } else {
                    state = result.getLeft();
                    list.add(result.getRight());
                }
            }
        }
        return Pair.of(state, list);
    }

    @Override
    public Collection<IdentityKey> getMembers(
            State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState> state) {
        return dcgkaProtocol.getMembers(state.dcgkaState);
    }

    @Override
    public Collection<IdentityKey> getMembersAndRemovedMembers(
            State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState> state) {
        return dcgkaProtocol.getMembersAndRemovedMembers(state.dcgkaState);
    }

    /**
     * Wraps content in a ModularMessage, which is processed, and then in a SignedMessage, which is serialized and
     * returned.  Not for Welcomes.
     */
    private Pair<State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState>, byte[]> wrapAndProcess(
            State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState> state,
            byte[] content, boolean isDcgka, boolean updateSignature) {
        Pair<DcgkaState, I> ordererInput = dcgkaProtocol.getOrdererInput(state.dcgkaState);
        state = state.setDcgkaState(ordererInput.getLeft());
        Triple<OrdererState, Orderer.OrderInfo, T> orderInfo =
                orderer.getNextOrderInfo(state.ordererState, ordererInput.getRight());
        state = state.setOrdererState(orderInfo.getLeft());
        ModularMessage modular = new ModularMessage(isDcgka, false, content,
                orderInfo.getMiddle());
        if (isDcgka) {
            // Process for myself
            Pair<State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState>, MessageEffect> effect =
                    process(state, modular, null, state.id, orderInfo.getRight());
            if (effect == null) throw new RuntimeException("process failed in wrapAndProcess");
            state = effect.getLeft();
        }

        SignatureState originalSignatureState = state.signatureState;
        if (updateSignature) {
            // Do a signature update.
            Pair<SignatureState, SignatureProtocol.Update> signatureUpdate = signatureProtocol.update(state.signatureState);
            state = state.setSignatureState(signatureUpdate.getLeft());
            modular.signatureUpdate = signatureUpdate.getRight();
        }
        ModularMessage.Serialized toSign = modular.serialize();
        // Note here we sign with originalSignatureProtocol, excluding any potential
        // signature update.
        SignedMessage signed = new SignedMessage(toSign, state.id,
                signatureProtocol.getSignature(originalSignatureState, toSign.getBytes()));
        return Pair.of(state, signed.serialize());
    }

    /**
     * Note if the message is a welcome, causalInfo is ignored in favor of whatever causalOrderer.processWelcomeInfo
     * returns.  Returns null on error, in which case the caller should silently drop this message and re-use the old
     * state.  {@code signed} should be {@code null} if and only if we are processing one of our messages.
     */
    public Pair<State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState>, MessageEffect> process(
            State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState> state,
            ModularMessage message, SignedMessage signed, IdentityKey sender, T causalInfo) {
        try {
            // Stuff for the eventual return value
            DgmMessageType type;
            byte[] responseMessage = null;
            byte[] plaintext = null;
            IdentityKey target = null;
            Collection<IdentityKey> added = Collections.emptyList();
            Collection<IdentityKey> removed = Collections.emptyList();
            Collection<?> ackedMessageIds = Collections.emptyList();
            Object messageId = null;

            // We use (signed == null) as a proxy for (it's from us)
            if (signed != null && sender.equals(state.id)) {
                Logger.i("ModularDsgm", state.id.hashCode() +
                        ": Message from outside purporting to be from us");
                return null;
            }
            if (signed == null) assertThat(sender).isEqualTo(state.id);

            if (signed != null) {
                // Check signature
                if (!signatureProtocol.verify(state.signatureState, message.isWelcome, signed.content.getBytes(),
                        sender, signed.signature)) {
                    Logger.i("ModularDsgm", state.id.hashCode() +
                            ": Invalid signature on ready message");
                    return null;
                }
                // Note we don't call processUpdate on our own signature updates
                if (!message.isWelcome && message.signatureUpdate.getBytes() != null) {
                    state = state.setSignatureState(signatureProtocol.processUpdate(state.signatureState,
                            message.signatureUpdate, sender));
                }
            }
            if (message.isWelcome) {
                if (state.isWelcomed) {
                    Logger.i("ModularDsgm", state.id.hashCode() +
                            ": Duplicate welcome");
                    return null;
                }
                Pair<OrdererState, T> ordererResult =
                        orderer.processWelcomeInfo(state.ordererState, message.orderInfo, sender);
                causalInfo = ordererResult.getRight();
                state = new State<>(state,
                        state.dcgkaState, ordererResult.getLeft(),
                        signatureProtocol.processWelcomeInfo(state.signatureState, message.signatureUpdate, sender),
                        true, state.forwardSecureEncryptionStates);
            } else {
                assertThat(state.isWelcomed).isTrue();
                if (!getMembersAndRemovedMembers(state).contains(sender)) {
                    throw new IllegalArgumentException("Unknown sender: " + sender.hashCode());
                }
                if (message.orderInfo.getBytes() == null) {
                    throw new IllegalArgumentException("orderInfo is null for message not from initial group creation");
                }
            }
            if (message.isDcgka) {
                DcgkaProtocol.ProcessReturn<DcgkaState> result = dcgkaProtocol.process(state.dcgkaState,
                        DcgkaProtocol.ControlMessage.of(message.content), sender, causalInfo);
                state = state.setDcgkaState(result.state);
                // Process new randomness
                if (result.updateSecret != null) {
                    if (signed == null) {
                        // It's my message, start a new epoch
                        state = state.putForwardSecureEncryptionProtocol(state.id,
                                forwardSecureEncryptionProtocol.init(result.updateSecret));
                    } else {
                        state = state.putForwardSecureEncryptionProtocol(sender,
                                forwardSecureEncryptionProtocol.init(result.updateSecret));
                    }
                }
                // Process response message
                if (result.responseMessage.getBytes() != null) {
                    assertThat(signed != null).isTrue(); // Processing our own message should not make a response
                    Pair<State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState>, byte[]> wrappedResponse =
                            wrapAndProcess(state, result.responseMessage.getBytes(), true, false);
                    state = wrappedResponse.getLeft();
                    responseMessage = wrappedResponse.getRight();
                }
                target = result.target;
                added = result.added;
                removed = result.removed;
                messageId = result.messageId;
                ackedMessageIds = result.ackedMessageIds;
                switch (result.type) {
                    case WELCOME:
                        type = DgmMessageType.WELCOME;
                        break;
                    case ADD:
                        type = DgmMessageType.ADD;
                        break;
                    case REMOVE:
                        type = DgmMessageType.REMOVE;
                        break;
                    case UPDATE:
                        type = DgmMessageType.UPDATE;
                        break;
                    default:
                        type = DgmMessageType.DCGKA_OTHER;
                }
            } else {
                assertThat(signed).isNotNull(); // should only be processing app messages from others
                ForwardSecureEncryptionState forwardSecureEncryptionState =
                        state.forwardSecureEncryptionStates.get(sender);
                if (forwardSecureEncryptionState == null) {
                    // Unable to decrypt
                    Logger.i("ModularDsgm", state.id.hashCode() +
                            ": No ForwardSecureEncryptionState for message with sender " +
                            sender.hashCode() + ".\nHopefully, this just means that the " +
                            "message was concurrent to our own addition.");
                    return null;
                }
                ForwardSecureEncryptionProtocol.DecryptionResult<ForwardSecureEncryptionState> fsAeSend = forwardSecureEncryptionProtocol.decrypt(forwardSecureEncryptionState, message.content);
                plaintext = fsAeSend.plaintext;
                if (plaintext == null) {
                    Logger.i("ModularDsgm", state.id.hashCode() +
                            ": Failed to decrypt application message, sender=" +
                            sender.hashCode());
                    return null;
                }
                state = state.putForwardSecureEncryptionProtocol(sender, fsAeSend.state);
                type = DgmMessageType.APPLICATION;
            }
            return Pair.of(state,
                    new MessageEffect(sender, type, responseMessage, plaintext, target, added, removed, messageId,
                            ackedMessageIds));
        } catch (IllegalArgumentException | IllegalStateException exc) {
            Logger.i("ModularDsgm", state.id.hashCode() +
                    ": Ignoring bad message in process, sender=" + sender.hashCode() +
                    ": " + exc);
            Logger.i("ModularDsgm", "    Stack trace: " + ExceptionUtils.getStackTrace(exc));
            return null;
        }
    }

    public static class State<
            DcgkaState extends DcgkaProtocol.State,
            ForwardSecureEncryptionState extends ForwardSecureEncryptionProtocol.State,
            OrdererState extends Orderer.State,
            SignatureState extends SignatureProtocol.State>
            implements DsgmProtocol.State {
        private final IdentityKey id;
        private final DcgkaState dcgkaState;
        // Note that we only need one ForwardSecureEncryptionState per group member because we assume that
        // all messages from a group member (not just DCGKA messages) are delivered in order.  If we allowed
        // reordering here like in Signal, then we would instead need to store them by their sender and
        // by epoch.
        private final HashPMap<IdentityKey, ForwardSecureEncryptionState> forwardSecureEncryptionStates;
        private final OrdererState ordererState;
        private final SignatureState signatureState;

        private final boolean isWelcomed; // whether we are in the group already

        public State(IdentityKey id, DcgkaState dcgkaState,
                     OrdererState ordererState, SignatureState signatureState) {
            this.id = id;
            this.dcgkaState = dcgkaState;
            this.ordererState = ordererState;
            this.signatureState = signatureState;
            this.isWelcomed = false;
            this.forwardSecureEncryptionStates = HashTreePMap.empty();
        }

        private State(State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState> other,
                      DcgkaState dcgkaState, OrdererState ordererState, SignatureState signatureState,
                      boolean isWelcomed,
                      HashPMap<IdentityKey, ForwardSecureEncryptionState> forwardSecureEncryptionStates) {
            this.id = other.id;
            this.dcgkaState = dcgkaState;
            this.ordererState = ordererState;
            this.signatureState = signatureState;
            this.isWelcomed = isWelcomed;
            this.forwardSecureEncryptionStates = forwardSecureEncryptionStates;
        }

        private State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState> setDcgkaState(
                DcgkaState newDcgkaState) {
            return new State<>(this, newDcgkaState, this.ordererState, this.signatureState, this.isWelcomed,
                    this.forwardSecureEncryptionStates);
        }

        private State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState> setOrdererState(
                OrdererState newOrdererState) {
            return new State<>(this, this.dcgkaState, newOrdererState, this.signatureState, this.isWelcomed,
                    this.forwardSecureEncryptionStates);
        }

        private State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState> setSignatureState(
                SignatureState newSignatureState) {
            return new State<>(this, this.dcgkaState, this.ordererState, newSignatureState, this.isWelcomed,
                    this.forwardSecureEncryptionStates);
        }

        private State<DcgkaState, ForwardSecureEncryptionState, OrdererState, SignatureState> putForwardSecureEncryptionProtocol(
                IdentityKey member, ForwardSecureEncryptionState forwardSecureEncryptionState) {
            return new State<>(this, this.dcgkaState, this.ordererState, this.signatureState, this.isWelcomed,
                    this.forwardSecureEncryptionStates.plus(member, forwardSecureEncryptionState));
        }
    }
}
