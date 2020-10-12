package org.trvedata.sgm;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.trvedata.sgm.crypto.IdentityKey;

import java.util.Collection;
import java.util.List;

/**
 * A {@link DsgmProtocol} is an implementation of a Decentralized Group Messaging protocol, which is
 * a complete end-to-end encrypted group messaging protocol, designed to work on top of a network
 * that provides reliable at-least-once broadcast message delivery but not other delivery or security
 * requirements.
 * <p>
 * To use a DgmProtocol, an application initializes a {@link DsgmProtocol} instance.
 * The application can then use {@link DsgmProtocol#create} to create a new group,
 * {@link DsgmProtocol#add} to add a user the current group, {@link DsgmProtocol#remove} to
 * remove a group member, {@link DsgmProtocol#update} to issue an update for post-compromise security,
 * or {@link DsgmProtocol#send} to encrypt a message.  In any case, the returned message should be
 * broadcast to other group members, who then call {@link DsgmProtocol#receive} on it.
 * This method returns the results of processing all messages that become ready as a result of the received
 * message (i.e., all of their necessary predecessors have been received).  Invalid messages are
 * ignored.  Note that {@link DsgmProtocol#receive} should not be called on our own messages, in
 * contrast to {@link DcgkaProtocol}.
 * <p>
 * {@link DsgmProtocol} objects should be immutable.  "Mutating" methods must return a new
 * {@link DsgmProtocol} while leaving the original unchanged.
 * <p>
 * Specific rules for message delivery:
 * <ul>
 *     <li>Messages should be broadcast to all current group members, except for a welcome
 *     message returned by {@link DsgmProtocol#add}, which need only be sent to the added user.</li>
 *     <li>Messages output by methods besides {@link DsgmProtocol#send} should
 *     also be broadcast to all concurrently added group members, as described in the paper draft.
 *     Depending on the precise protocol implementation, this may also be required for
 *     outputs of {@link DsgmProtocol#send}.</li>
 *     <li>Messages should be delivered at least once, but multiple times is okay.</li>
 *     <li>Including extra unrelated or even malicious messages is okay.</li>
 * </ul>
 * However, all group members are assumed to honestly follow the protocol.
 * <p>
 */
public interface DsgmProtocol<S extends DsgmProtocol.State> {
    /**
     * Members must NOT include us.
     */
    Pair<S, byte[]> create(S state, Collection<IdentityKey> members);

    /**
     * Future TODO: For this prototype, we assume that no {@code IdentityKey} will be added to a group more than once
     * (e.g., from concurrent adds, or from being removed and added back again).
     *
     * @return (updated state, welcome message for added member only, add message to be broadcast to existing members).
     */
    Triple<S, byte[], byte[]> add(S state, IdentityKey added);

    Pair<S, byte[]> remove(S state, IdentityKey removed);

    Pair<S, byte[]> update(S state);

    Pair<S, byte[]> send(S state, byte[] plaintext);

    /**
     * @return (updated state after all processed messages, ordered list of results of processing
     *messages that became ready from { @ code message })).
     */
    Pair<S, List<MessageEffect>> receive(S state, byte[] message);

    /**
     * Returns the current set of group members.
     *
     * @param state The state to reference (immutably).
     * @return The current set of group members.
     */
    Collection<IdentityKey> getMembers(S state);

    /**
     * Returns all users who have ever been added to the group, even if they were since
     * removed or their addition was cancelled immediately.
     *
     * @param state The state to reference (immutably).
     * @return The set of group members and removed group members.
     */
    Collection<IdentityKey> getMembersAndRemovedMembers(S state);

    enum DgmMessageType {WELCOME, ADD, REMOVE, UPDATE, DCGKA_OTHER, APPLICATION}

    /**
     * Structure describing the effect of a message passed to {@link DsgmProtocol#receive}
     * that has become ready and hence been processed.
     */
    final class MessageEffect {
        /**
         * The message's sender.
         */
        public final IdentityKey sender;
        /**
         * The type of the processed message.
         * acks fall under DcgkaOther.
         */
        public final DgmMessageType type;
        /**
         * A message that should be broadcast to the other group members in response to
         * the processed message, or null if there is no response.
         */
        public final byte[] responseMessage;
        /**
         * The decrypted application plaintext given by this message, or null if {@link MessageEffect#type}
         * is not Application.
         */
        public final byte[] plaintext;
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
         * and adds can cause removed users or vice-versa.  Empty if irrelevant.
         */
        public final Collection<IdentityKey> added;
        /**
         * The set of users removed by {@code message}.  Specifically, this is the remove delta between the
         * resulting set of group members and the previous set of group members.  Depending on the
         * Decentralized Group Membership protocol in use and the concurrency relations between messages,
         * add and remove messages may add/remove more users than directly intended by the sender,
         * and adds can cause removed users or vice-versa.  Empty if irrelevant.  This may include us,
         * indicating that we were removed the by the message, hence we did not process it (besides
         * observing that it removed us).
         */
        public final Collection<IdentityKey> removed;
        /**
         * An opaque identifier for this message, that will be used to reference this message in future
         * messages' {@code ackedMessageIds} fields.  Identifiers should be compared using
         * {@link Object#equals}, not {@code ==}.  This is only used for some DCKGA messages.
         * Null if irrelevant.
         */
        public final Object messageId;
        /**
         * The set of messages acknowledged by {@code message}'s sender, identified using the
         * {@link MessageEffect#messageId} fields returned when those messages were originally processed.
         * Note that any non-WELCOME message may have acks, in addition to its core
         * functionality.  Empty if irrelevant.
         */
        public final Collection<? extends Object> ackedMessageIds;

        public MessageEffect(IdentityKey sender, DgmMessageType type, byte[] responseMessage,
                             byte[] plaintext, IdentityKey target,
                             Collection<IdentityKey> added, Collection<IdentityKey> removed,
                             Object messageId, Collection<? extends Object> ackedMessageIds) {
            this.sender = sender;
            this.type = type;
            this.responseMessage = responseMessage;
            this.plaintext = plaintext;
            this.target = target;
            this.added = added;
            this.removed = removed;
            this.messageId = messageId;
            this.ackedMessageIds = ackedMessageIds;
        }
    }

    interface State {
    }
}
