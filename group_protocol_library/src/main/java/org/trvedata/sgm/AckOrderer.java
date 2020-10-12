package org.trvedata.sgm;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.apache.thrift.TException;
import org.pcollections.ConsPStack;
import org.pcollections.HashPMap;
import org.pcollections.HashTreePMap;
import org.pcollections.TreePVector;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.message.AckOrdererTimestamp;
import org.trvedata.sgm.message.MessageId;
import org.trvedata.sgm.misc.Logger;
import org.trvedata.sgm.misc.Utils;

import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link Orderer} which orders messages using the rules:
 * <ol>
 *     <li>All messages by the same sender are delivered in order.</li>
 *     <li>DCGKA Add, Remove, and Update messages are causally ordered.</li>
 *     <li>DCGKA Other messages are
 *     delivered after any causally prior Add, Remove, or Update messages, but not necessarily
 *     after causally prior Other messages.</li>
 *     <li>The DCGKA Welcome message adding us to the group, which must be unique, is delivered
 *     before any other messages.  Subsequently, messages concurrent to or causally greater than
 *     the corresponding Add message/group creation are delivered, while messages causally
 *     less than the corresponding Add message are ignored.</li>
 * </ol>
 * <p>
 * Causality information for DCGKA messages is returned in the form of a {@link VectorClock}.  The
 * entries in these vector clocks count all messages by a user, starting at 1, but they are only
 * updated to reflect DCGKA Add, Remove, and Update messages, so entries may skip numbers and are
 * not updated immediately after DCGKA Other messages and application messages.
 * <p>
 * Internally, causality is tracked using acknowledgements of previous messages: each DCGKA message includes
 * the message ids of all DCGKA Add, Remove, and Update messages from other users that have been delivered
 * (via {@link AckOrderer#getReadyMessage}) but not yet acknowledged.  When using {@link FullDcgkaProtocol},
 * since the DCGKA sends an acknowledgment immediately after receiving such a message, each
 * orderInfo contains at most one acknowledgment.
 *
 * @param <M> The type of messages.
 */
public class AckOrderer<M> implements Orderer<M, AckOrderer.Timestamp, MessageId, AckOrderer.State<M>> {

    @Override
    public State<M> queue(State<M> state, M message, IdentityKey sender, OrderInfo orderInfo) {
        if (state.welcomeClock == null) {
            // not yet initialized via processWelcome
            return state.addToWaitingForWelcome(message, sender, orderInfo);
        }
        Timestamp timestamp = new Timestamp(orderInfo, sender);
        // Drop messages that we've already processed.  This includes
        // messages causally prior to our welcome (including the message adding us)
        if (timestamp.messageId.number <= state.clock.get(sender)) {
            if (timestamp.messageId.number <= state.welcomeClock.get(sender)) {
                Logger.i("AckOrderer", state.id.hashCode() + ": (queue) Ignoring message from before our addition: " +
                        timestamp.messageId);
            } else {
                Logger.i("AckOrderer", state.id.hashCode() + ": (queue) Ignoring message we already processed: " +
                        timestamp.messageId);
            }
            return state;
        }
        ConsPStack<Pair<M, Timestamp>> newReadyMessages = state.readyMessages;
        HashPMap<MessageId, TreePVector<Pair<M, Timestamp>>> newUnreadyMessages = state.unreadyMessages;
        if (state.clock.get(sender) != timestamp.messageId.number - 1) {
            // Not ready due to sender's previous message.
            /*Logger.d("AckOrderer", state.id.hashCode() + ": (queue) Not ready due to sender's previous message: " +
                    timestamp.messageId + ", clock: " + state.clock);*/
            newUnreadyMessages = Utils.putMulti(newUnreadyMessages, new MessageId(sender, timestamp.messageId.number - 1),
                    Pair.of(message, timestamp));
        } else {
            if (timestamp.ackedMessageId != null &&
                    (state.clock.get(timestamp.ackedMessageId.author) < timestamp.ackedMessageId.number)) {
                // Not ready due to ack.
                /*Logger.d("AckOrderer", state.id.hashCode() + ": (queue) Not ready due to ack: " +
                        timestamp.messageId + ", ack: " + timestamp.ackedMessageId + ", clock: " + state.clock);*/
                newUnreadyMessages = Utils.putMulti(newUnreadyMessages, timestamp.ackedMessageId,
                        Pair.of(message, timestamp));
            } else {
                // Ready.
                newReadyMessages = newReadyMessages.plus(Pair.of(message, timestamp));
            }
        }
        return new State<>(state.id, state.clock, state.welcomeClock, state.waitingForWelcome, newReadyMessages,
                newUnreadyMessages);
    }

    @Override
    public ReadyMessage<M, Timestamp, State<M>> getReadyMessage(State<M> state) {
        // Loop until we find a ready message that is not a duplicate of a previously processed MessageId.
        ConsPStack<Pair<M, Timestamp>> newReadyMessages = state.readyMessages;
        while (!newReadyMessages.isEmpty()) {
            Pair<M, Timestamp> message = newReadyMessages.get(0);
            newReadyMessages = newReadyMessages.minus(0);
            MessageId messageId = message.getRight().messageId;
            if (state.clock.get(messageId.author) >= messageId.number) {
                // We've already processed a message with the same MessageId, skip it.
                Logger.i("AckOrderer", state.id.hashCode() + ": (ready) Ignoring duplicate message: " +
                        messageId);
                continue;
            }
            assertThat(messageId.number).isEqualTo(state.clock.get(messageId.author) + 1);
            // See if any successors become ready.
            state = state.setClock(state.clock.increment(messageId.author));
            HashPMap<MessageId, TreePVector<Pair<M, Timestamp>>> newUnreadyMessages = state.unreadyMessages;
            Collection<Pair<M, Timestamp>> successors = state.unreadyMessages.get(messageId);
            if (successors != null && !successors.isEmpty()) {
                newUnreadyMessages = newUnreadyMessages.minus(messageId);
                for (Pair<M, Timestamp> successor : successors) {
                    MessageId successorId = successor.getRight().messageId;
                    if (state.clock.get(successorId.author) >= successorId.number) {
                        // We've already processed a message with the same MessageId, skip it.
                        Logger.i("AckOrderer", state.id.hashCode() + ": (ready) Ignoring duplicate message: " +
                                successorId);
                        continue;
                    }
                    // Unready messages are stored first keyed by their sender's previous message and then by their
                    // ack.  Hence to check readiness, we now only have to check for their ack.
                    if (successor.getRight().ackedMessageId != null &&
                            state.clock.get(successor.getRight().ackedMessageId.author) <
                                    successor.getRight().ackedMessageId.number) {
                        // Not ready due to ack
                        /*Logger.d("AckOrderer", state.id.hashCode() + ": (ready) Not ready due to ack: " +
                                successor.getRight().messageId + ", ack: " + successor.getRight().ackedMessageId +
                                ", clock: " + state.clock);*/
                        newUnreadyMessages = Utils.putMulti(newUnreadyMessages, successor.getRight().ackedMessageId,
                                successor);
                    } else {
                        newReadyMessages = newReadyMessages.plus(successor);
                    }
                }
            }
            return new ReadyMessage<>(new State<>(state.id, state.clock,
                    state.welcomeClock, state.waitingForWelcome, newReadyMessages, newUnreadyMessages),
                    message.getLeft(), messageId.author, message.getRight());
        }
        // If we got here, no messages are ready.
        return null;
    }

    @Override
    public State<M> skipReadyMessage(State<M> state) {
        ConsPStack<Pair<M, Timestamp>> newReadyMessages = state.readyMessages;
        // Loop until we find a message that is not a duplicate of a previously processed message,
        // skipping that and the rest
        while (!newReadyMessages.isEmpty()) {
            Pair<M, Timestamp> message = newReadyMessages.get(0);
            newReadyMessages = newReadyMessages.minus(0);
            MessageId messageId = message.getRight().messageId;
            if (state.clock.get(messageId.author) < messageId.number) {
                // This message is not a duplicate, we're done
                break;
            }
        }
        return new State<>(state.id, state.clock, state.welcomeClock, state.waitingForWelcome, newReadyMessages,
                state.unreadyMessages);
    }

    @Override
    public Triple<State<M>, OrderInfo, Timestamp> getNextOrderInfo(State<M> state, MessageId ack) {
        VectorClock newClock = state.clock.increment(state.id);
        Timestamp timestamp = new Timestamp(new MessageId(state.id, newClock.get(state.id)),
                ack, null);
        return Triple.of(new State<>(state.id, newClock, state.welcomeClock, state.waitingForWelcome,
                state.readyMessages, state.unreadyMessages), timestamp.serialize(), timestamp);
    }

    @Override
    public Pair<State<M>, Timestamp> processWelcomeInfo(State<M> state, OrderInfo welcomeInfo, IdentityKey sender) {
        VectorClock clock;
        if (welcomeInfo.getBytes() == null) {
            // from group creation
            // Incrementing here is not actually necessary, as all initial group members will initialize to the
            // same timestamp (they all reach this if statement), and the protocol will work as long as
            // they all start with the same timestamp.  Nonetheless, we increment so that the group creator's
            // first message number is 1 instead of 0, like everyone else.
            clock = (new VectorClock(sender, HashTreePMap.empty())).increment(sender);
        } else clock = new VectorClock(welcomeInfo.getBytes());
        MessageId messageId = new MessageId(sender, clock.get(sender));
        TreePVector<Triple<M, IdentityKey, OrderInfo>> waitingForWelcome = state.waitingForWelcome;
        state = new State<>(state.id, clock, clock, null, ConsPStack.empty(), HashTreePMap.empty());
        // Actually queue messages that were queued before the welcome
        for (Triple<M, IdentityKey, OrderInfo> queued : waitingForWelcome) {
            state = queue(state, queued.getLeft(), queued.getMiddle(), queued.getRight());
        }
        return Pair.of(state, new Timestamp(messageId, null, clock));
    }

    @Override
    public OrderInfo getWelcomeInfo(State<M> state) {
        return OrderInfo.of(state.clock.serialize());
    }

    public static class Timestamp {
        /**
         * For welcome info, corresponds to add, else corresponds to message itself.
         */
        public final MessageId messageId;
        /**
         * Non-null only for an ack.
         */
        public final MessageId ackedMessageId;
        /**
         * Non-null only for welcome info.  Corresponds to add.
         */
        public final VectorClock clock;

        private Timestamp(MessageId messageId, MessageId ackedMessageId, VectorClock clock) {
            this.messageId = messageId;
            this.ackedMessageId = ackedMessageId;
            this.clock = clock;
        }

        private Timestamp(OrderInfo serialized, IdentityKey sender) {
            try {
                AckOrdererTimestamp deserialized = new AckOrdererTimestamp();
                Utils.deserialize(deserialized, serialized.getBytes());
                messageId = new MessageId(sender, deserialized.getNumber());
                if (deserialized.isSetAckAuthor()) {
                    ackedMessageId = new MessageId(new IdentityKey(deserialized.getAckAuthor()),
                            deserialized.getAckNumber());
                } else ackedMessageId = null;
                if (deserialized.isSetClock()) {
                    clock = new VectorClock(deserialized.getClock());
                } else clock = null;
            } catch (TException | IllegalArgumentException exc) {
                throw new IllegalArgumentException("Failed to deserialize Timestamp", exc);
            }
        }

        private OrderInfo serialize() {
            AckOrdererTimestamp serialized = new AckOrdererTimestamp(messageId.number);
            if (ackedMessageId != null) {
                serialized.setAckAuthor(ackedMessageId.author.serialize());
                serialized.setAckNumber(ackedMessageId.number);
            }
            if (clock != null) {
                serialized.setClock(clock.serialize());
            }
            return OrderInfo.of(Utils.serialize(serialized));
        }
    }

    public static class State<M> implements Orderer.State {
        private final IdentityKey id;
        private final VectorClock clock;
        private final VectorClock welcomeClock; // timestamp of the add/create that added us.  Null if
        // processWelcome has not yet been called.
        private final TreePVector<Triple<M, IdentityKey, OrderInfo>> waitingForWelcome; // Messages that were queued when
        // processWelcome has not yet been called.  Null if it was called already.
        private final ConsPStack<Pair<M, Timestamp>> readyMessages;
        /* Maps from a MessageId to a collection of messages that are immediate successors of that message,
        i.e., they either ack that message, or they are the next message by the same sender.  Each message
        appears at most once as a value.  In case both the ack and the sender's previous message are missing,
        we first add a message keyed under the sender's previous message, then under its ack.
         */
        private final HashPMap<MessageId, TreePVector<Pair<M, Timestamp>>> unreadyMessages;

        private State(IdentityKey id, VectorClock clock, VectorClock welcomeClock,
                      TreePVector<Triple<M, IdentityKey, OrderInfo>> waitingForWelcome,
                      ConsPStack<Pair<M, Timestamp>> readyMessages,
                      HashPMap<MessageId, TreePVector<Pair<M, Timestamp>>> unreadyMessages) {
            this.id = id;
            this.clock = clock;
            this.welcomeClock = welcomeClock;
            this.waitingForWelcome = waitingForWelcome;
            this.readyMessages = readyMessages;
            this.unreadyMessages = unreadyMessages;
        }

        public State(IdentityKey id) {
            // The null values are initialized in processWelcomeInfo, which everyone calls when
            // they are added to the group (including the group creator).
            this(id, null, null, TreePVector.empty(), null, null);
        }

        private State<M> addToWaitingForWelcome(M message, IdentityKey sender, OrderInfo orderInfo) {
            return new State<>(this.id, this.clock, this.welcomeClock,
                    this.waitingForWelcome.plus(Triple.of(message, sender, orderInfo)), this.readyMessages,
                    this.unreadyMessages);
        }

        public State<M> setClock(VectorClock newClock) {
            return new State<>(this.id, newClock, this.welcomeClock, this.waitingForWelcome, this.readyMessages,
                    this.unreadyMessages);
        }
    }
}
