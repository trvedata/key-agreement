package org.trvedata.sgm.trivial;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.apache.thrift.TException;
import org.trvedata.sgm.AckOrderer;
import org.trvedata.sgm.DcgkaProtocol;
import org.trvedata.sgm.ForwardSecureEncryptionProtocol;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.message.FullDcgkaMessageType;
import org.trvedata.sgm.message.MessageId;
import org.trvedata.sgm.message.TrivialDcgkaMessage;
import org.trvedata.sgm.misc.Constants;
import org.trvedata.sgm.misc.Logger;
import org.trvedata.sgm.misc.Utils;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;


/**
 * Trivial implementation of {@link DcgkaProtocol}, which fulfills all the
 * class's contracts but does not do any cryptography.  This class does still deliver and process
 * group membership operations, using a 2-phase set CRDT as the membership set (i.e., removed users
 * remain removed forever even if they are added again).  Also, Add, Remove, and Update
 * messages are acked, and {@link DcgkaProtocol#getOrdererInput} can be used along with
 * {@link AckOrderer} to enforce causally ordered delivery.
 */
public class TrivialDcgkaProtocol implements DcgkaProtocol<AckOrderer.Timestamp, MessageId, TrivialDcgkaProtocol.State> {

    @Override
    public Pair<State, ControlMessage> create(State state, Collection<IdentityKey> members) {
        TrivialDcgkaMessage message = new TrivialDcgkaMessage(FullDcgkaMessageType.CREATE,
                new ArrayList<>(), new ArrayList<>());
        for (IdentityKey member : members) {
            message.addToAdded(ByteBuffer.wrap(member.serialize()));
        }
        return Pair.of(state, ControlMessage.of(Utils.serialize(message)));
    }

    @Override
    public Triple<State, ControlMessage, ControlMessage> add(State state, IdentityKey added) {
        TrivialDcgkaMessage add = new TrivialDcgkaMessage(FullDcgkaMessageType.ADD,
                new ArrayList<>(), new ArrayList<>());
        add.addToAdded(ByteBuffer.wrap(added.serialize()));
        TrivialDcgkaMessage welcome = new TrivialDcgkaMessage(FullDcgkaMessageType.WELCOME,
                new ArrayList<>(), new ArrayList<>());
        for (IdentityKey member : state.members) {
            welcome.addToAdded(ByteBuffer.wrap(member.serialize()));
        }
        welcome.addToAdded(ByteBuffer.wrap(added.serialize()));
        return Triple.of(state, ControlMessage.of(Utils.serialize(welcome)), ControlMessage.of(Utils.serialize(add)));
    }

    @Override
    public Pair<State, ControlMessage> remove(State state, IdentityKey removed) {
        TrivialDcgkaMessage message = new TrivialDcgkaMessage(FullDcgkaMessageType.REMOVE,
                new ArrayList<>(), new ArrayList<>());
        message.addToRemoved(ByteBuffer.wrap(removed.serialize()));
        return Pair.of(state, ControlMessage.of(Utils.serialize(message)));
    }

    @Override
    public Pair<State, ControlMessage> update(State state) {
        TrivialDcgkaMessage message = new TrivialDcgkaMessage(FullDcgkaMessageType.UPDATE,
                new ArrayList<>(), new ArrayList<>());
        return Pair.of(state, ControlMessage.of(Utils.serialize(message)));
    }

    @Override
    public ProcessReturn<State> process(State state, ControlMessage message, IdentityKey sender,
                                        AckOrderer.Timestamp causalInfo) {
        try {
            HashSet<IdentityKey> newMembers = (HashSet<IdentityKey>) state.members.clone();
            HashSet<IdentityKey> newRemovedMembers = (HashSet<IdentityKey>) state.removedMembers.clone();
            IdentityKey target = null;
            TrivialDcgkaMessage deserialized = new TrivialDcgkaMessage();
            Utils.deserialize(deserialized, message.getBytes());
            DcgkaMessageType type;
            switch (deserialized.getType()) {
                case CREATE:
                case WELCOME:
                    type = DcgkaMessageType.WELCOME;
                    break;
                case ADD:
                    type = DcgkaMessageType.ADD;
                    break;
                case REMOVE:
                    type = DcgkaMessageType.REMOVE;
                    break;
                case UPDATE:
                    type = DcgkaMessageType.UPDATE;
                    break;
                default:
                    type = DcgkaMessageType.OTHER;
            }
            byte[] updateSecret = new byte[Constants.KEY_SIZE_BYTES]; // fake epoch update
            ArrayList<IdentityKey> added = new ArrayList<>();
            for (ByteBuffer oneAdd : deserialized.getAdded()) {
                IdentityKey asKey = new IdentityKey(Utils.asArray(oneAdd));
                if (!newMembers.contains(asKey) && !newRemovedMembers.contains(asKey)) added.add(asKey);
            }
            ArrayList<IdentityKey> removed = new ArrayList<>();
            for (ByteBuffer oneRemove : deserialized.getRemoved()) {
                IdentityKey asKey = new IdentityKey(Utils.asArray(oneRemove));
                if (!newRemovedMembers.contains(asKey)) removed.add(asKey);
            }
            if (type == DcgkaMessageType.WELCOME && !added.contains(state.id)) {
                // Throw an exception, to fulfill the condition stated in the Javadoc for DcgkaProtocol.process.
                String messageIdString = "";
                if (causalInfo != null) {//happens with TrivialOrderer
                    messageIdString = ": " + causalInfo.messageId;
                }
                throw new IllegalArgumentException("Welcome is not for us" + messageIdString);
            }
            newMembers.addAll(added);
            newMembers.removeAll(removed);
            newRemovedMembers.addAll(removed);
            if (type == DcgkaMessageType.ADD) {
                target = new IdentityKey(Utils.asArray(deserialized.getAdded().get(0)));
            }
            if (type == DcgkaMessageType.REMOVE)
                target = new IdentityKey(Utils.asArray(deserialized.getRemoved().get(0)));
            byte[] responseMessage = null;
            MessageId ackedMessage = null;
            if (type != DcgkaMessageType.OTHER) {
                if (!sender.equals(state.id) && !newRemovedMembers.contains(state.id)) {
                    // send a (non-specific) ack, to trigger key updates
                    TrivialDcgkaMessage ack = new TrivialDcgkaMessage(FullDcgkaMessageType.ACK,
                            new ArrayList<>(), new ArrayList<>());
                    responseMessage = Utils.serialize(ack);
                    if (causalInfo != null) {//happens with TrivialOrderer
                        ackedMessage = causalInfo.messageId;
                    }
                }
            }
            // Note: unlike FullDcgkaProtocol, we don't ensure that we don't process messages from a user that
            // causally depend on their removal.  This happens anyway for honest users, since they won't
            // accept their own removal message, hence won't ack it or anything later.
            ArrayList<Object> ackedMessages = new ArrayList<>();
            if (causalInfo != null && causalInfo.ackedMessageId != null) ackedMessages.add(causalInfo.ackedMessageId);
            return new ProcessReturn<>(new State(state.id, newMembers, newRemovedMembers,
                    ackedMessage), type, ControlMessage.of(responseMessage),
                    ForwardSecureEncryptionProtocol.Key.of(updateSecret), target, added, removed,
                    ((causalInfo == null) ? null : causalInfo.messageId),
                    ackedMessages);
        } catch (TException | IllegalArgumentException exc) {
            Logger.w("TrivialDcgkaProtocol", "Failed to deserialize in process");
            throw new IllegalArgumentException("Failed to deserialize in process", exc);
        }
    }

    public Pair<State, MessageId> getOrdererInput(State state) {
        State newState = state;
        if (state.lastAcked != null) {
            // Set lackAcked to null so we only send each ack once.
            newState = new State(state.id, state.members, state.removedMembers, null);
        }
        return Pair.of(newState, state.lastAcked);
    }

    @Override
    public Collection<IdentityKey> getMembers(State state) {
        return state.members;
    }

    @Override
    public Collection<IdentityKey> getMembersAndRemovedMembers(State state) {
        return CollectionUtils.union(state.members, state.removedMembers);
    }

    public static class State implements DcgkaProtocol.State {
        private final IdentityKey id;
        private final HashSet<IdentityKey> members;
        private final HashSet<IdentityKey> removedMembers;
        private final MessageId lastAcked; // last message that was acked

        private State(IdentityKey id, HashSet<IdentityKey> members, HashSet<IdentityKey> removedMembers,
                      MessageId lastAcked) {
            this.id = id;
            this.members = members;
            this.removedMembers = removedMembers;
            this.lastAcked = lastAcked;
        }

        public State(IdentityKey id) {
            this(id, new HashSet<>(), new HashSet<>(), null);
        }
    }
}
