package org.trvedata.sgm;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.misc.ByteHolder;

import java.util.Collection;

/**
 * A {@link DcgkaProtocol} is an implementation of a DCGKA scheme as described in the current paper draft.
 * Methods {@link DcgkaProtocol#create}, {@link DcgkaProtocol#add}, {@link DcgkaProtocol#remove},
 * {@link DcgkaProtocol#update}, and {@link DcgkaProtocol#process} have the same signatures
 * and contracts as described in the paper draft, except that we use object methods instead of
 * explicitly passing states.
 * <p>
 * {@link DcgkaProtocol} objects should be immutable.  "Mutating" methods must return a new
 * {@link DcgkaProtocol} while leaving the original unchanged.
 *
 * @param <T> The type of timestamps used by the {@link Orderer}.
 * @param <I> The type of extra input passed to {@link Orderer#getNextOrderInfo} from {@link DcgkaProtocol#getOrdererInput}.
 */
public interface DcgkaProtocol<T, I, S extends DcgkaProtocol.State> {
    /**
     * Members must NOT include us, as in the paper.
     */
    Pair<S, ControlMessage> create(S state, Collection<IdentityKey> members);

    /**
     * As in the paper draft, the return order is (welcome, add).
     */
    Triple<S, ControlMessage, ControlMessage> add(S state, IdentityKey added);

    Pair<S, ControlMessage> remove(S state, IdentityKey removed);

    Pair<S, ControlMessage> update(S state);

    /**
     * {@code causalInfo} is of parameter type {@code T}, so it need not be exactly
     * of the form described in the paper draft, although it should encode roughly that information.
     * <p>
     * Detail: unlike with non-welcome messages, the Orderer does not filter out welcome messages that
     * are not for us but that we receive before our actual welcome message.  (After we receive our actual
     * welcome message, ModularDgm rejects future welcome messages.)  Thus this method should make sure
     * to throw an IllegalArgumentException if it is passed a welcome message not intended for us.
     * Doing so is particularly important because in the testing setup, every message is delivered to
     * every client (even ones not yet added), including the group creation message.  It also prevents
     * an adversary from disrupting the protocol by replaying the group creation message to a non-initial user.
     * <p>
     * If the return value indicates that this message removed us, it should be treated like a null value,
     * so that the Orderer won't let us process messages that causally depend on it.
     */
    ProcessReturn<S> process(S state, ControlMessage message, IdentityKey sender, T causalInfo);

    /**
     * Returns (updated state, input to pass to {@link Orderer#getNextOrderInfo} for the most recently
     * generated message).
     */
    Pair<S, I> getOrdererInput(S state);

    /**
     * Returns the current set of group members.
     *
     * @return The current set of group members.
     */
    Collection<IdentityKey> getMembers(S state);

    /**
     * Returns all users who have ever been added to the group, even if they were since
     * removed or their addition was cancelled immediately.
     *
     * @return The set of group members and removed group members.
     */
    Collection<IdentityKey> getMembersAndRemovedMembers(S state);

    enum DcgkaMessageType {WELCOME, ADD, REMOVE, UPDATE, OTHER}

    /**
     * Structure used to return multiple values from {@link DcgkaProtocol#process}.
     */
    final class ProcessReturn<S extends State> {
        /**
         * The resulting state.
         */
        public final S state;
        /**
         * The type of the processed message.
         */
        public final DcgkaMessageType type;
        /**
         * The control message T' output by {@link DcgkaProtocol:process}, or a message with
         * {@code null} contents if
         * no message is output.
         */
        public final ControlMessage responseMessage;
        /**
         * The update secret I output by {@link DcgkaProtocol:process}, or a key with {@code null} contents if
         * no update secret is output.
         */
        public final ForwardSecureEncryptionProtocol.Key updateSecret;
        /**
         * For add and remove messages, the user intended to be added or removed.
         * This user will also be included in added or removed as appropriate, but only if
         * they are actually added or removed relative to the prior group state.
         * {@code null} for other message types.
         */
        public final IdentityKey target;
        /**
         * The set of users added by {@code message}.  Specifically, this is the add delta between the
         * resulting set of group members and the previous set of group members.  Depending on the
         * Decentralized Group Membership protocol in use and the concurrency relations between messages,
         * add and remove messages may add/remove more users than directly intended by the sender,
         * and adds can cause removed users or vice-versa.
         */
        public final Collection<IdentityKey> added;
        /**
         * The set of users removed by {@code message}.  Specifically, this is the remove delta between the
         * resulting set of group members and the previous set of group members.  Depending on the
         * Decentralized Group Membership protocol in use and the concurrency relations between messages,
         * add and remove messages may add/remove more users than directly intended by the sender,
         * and adds can cause removed users or vice-versa.
         */
        public final Collection<IdentityKey> removed;
        /**
         * An opaque identifier for this message, that will be used to reference this message in future
         * messages' {@code ackedMessageIds} fields.  Identifiers should be compared using
         * {@link Object#equals}, not {@code ==}.
         */
        public final Object messageId;
        /**
         * The set of messages acknowledged by {@code message}'s sender, identified using the
         * {@link ProcessReturn#messageId} fields returned when those messages were originally processed.
         * Note that any non-WELCOME message may have acks, in addition to its core add/remove/update/other
         * functionality.
         */
        public final Collection<? extends Object> ackedMessageIds;

        public ProcessReturn(S state, DcgkaMessageType type, ControlMessage responseMessage,
                             ForwardSecureEncryptionProtocol.Key updateSecret,
                             IdentityKey target,
                             Collection<IdentityKey> added, Collection<IdentityKey> removed,
                             Object messageId, Collection<? extends Object> ackedMessageIds) {
            this.state = state;
            this.type = type;
            this.responseMessage = responseMessage;
            this.updateSecret = updateSecret;
            this.target = target;
            this.added = added;
            this.removed = removed;
            this.messageId = messageId;
            this.ackedMessageIds = ackedMessageIds;
        }
    }

    class ControlMessage extends ByteHolder {
        public ControlMessage(byte[] bytes) {
            super(bytes);
        }

        public static ControlMessage of(byte[] bytes) {
            return new ControlMessage(bytes);
        }
    }

    interface State {
    }
}
