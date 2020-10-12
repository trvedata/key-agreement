package org.trvedata.sgm;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.misc.ByteHolder;

/**
 * A {@link Orderer} is the interface used by
 * {@link ModularDsgm} to attach timestamps to sent messages, buffer received messages and
 * deliver them in causal order, and pass causality information to the DcgkaProtocol.
 * <p>
 * {@link Orderer} objects should be immutable.  "Mutating" methods must return a new
 * {@link Orderer} while leaving the original unchanged.
 *
 * @param <M> The type of buffered messages, included as a type parameter to avoid
 *            unnecessary casting or internal serialization and deserialization.  It should be generic
 *            for each implementing subclass.
 * @param <T> The type of timestamps used by the implementing subclass, meant to be specified
 *            by each subclass.
 * @param <I> The type of extra input to {@link Orderer#getNextOrderInfo} from {@link DcgkaProtocol#getOrdererInput}.
 * @param <S> The state type.
 */
public interface Orderer<M, T, I, S extends Orderer.State> {

    /**
     * Queue {@code message} with the given metadata for later delivery.  Once all of {@code message}'s
     * predecessors have been delivered, it will be returned by {@link Orderer#getReadyMessage}.
     * {@code message} may also be silently dropped,
     * e.g., if it is causally prior to our addition to the group or already queued.
     * This may be called before the state is initialized with {@link Orderer#processWelcomeInfo},
     * in which case the message should be queued until after {@link Orderer#processWelcomeInfo}
     * is called.
     *
     * @param state     The state to reference (immutably).
     * @param message   The message to queue.
     * @param sender    The public {@link IdentityKey} of {@code message}'s sender.
     * @param orderInfo The {@code orderInfo} coming from {@code sender}'s call to
     *                  {@link Orderer#getNextOrderInfo}.
     * @return The updated state.
     */
    S queue(S state, M message, IdentityKey sender, OrderInfo orderInfo);

    /**
     * Returns a {@link Orderer.ReadyMessage} describing a message that is ready
     * for processing.  This will not be called until after the state is initialized
     * with {@link Orderer#processWelcomeInfo}.
     *
     * @param state The state to reference (immutably).
     * @return A message that is ready for processing, or null if no messages are ready, in which case
     * this object's state is still valid.
     */
    ReadyMessage<M, T, S> getReadyMessage(S state);

    /**
     * Return the state resulting from skipping the next message to be returned by
     * {@link Orderer#getReadyMessage}, treating it as a non-message.  E.g., don't increment
     * its sender's vector clock entry.  This is called when the next ready message turns
     * out to be invalid.  In particular, it will only be called on states where
     * {@link Orderer#getReadyMessage} is not {@code null}.
     *
     * @param state The state to reference (immutably).
     * @return The resulting state.
     */
    S skipReadyMessage(S state);

    /**
     * Returns the {@link OrderInfo} and timestamp of our next message, modifying the internal
     * state so that future calls to this method will give causally later results.  For example, using
     * vector clocks, this method would increment our entry in the vector clock, then return
     * serialized and non-serialized versions of the resulting vector clock.
     *
     * @param state      The state to reference (immutably).
     * @param dcgkaInput Extra info about the message from {@link DcgkaProtocol#getOrdererInput}.
     * @return (updated state, { @ link OrderInfo }, timestamp).  The order info is attached to the message and sent
     * to other group members, who pass it to {@link Orderer#queue}, while timestamp is passed to
     * our own {@link DcgkaProtocol#process} method.
     */
    Triple<S, OrderInfo, T> getNextOrderInfo(S state, I dcgkaInput);

    /**
     * Initialize a state with the given {@code welcomeInfo}, which comes from a call to
     * {@link Orderer#getWelcomeInfo} by the group member that added us, or is a wrapper around
     * {@code null} if the group was
     * created with us as a member (including the case that we created the group).
     *
     * @param state       The state to reference (immutably).
     * @param welcomeInfo The output of our adder's call to {@link Orderer#getWelcomeInfo}, or
     *                    a wrapper around {@code null} if the group was created with us as a member.
     * @param sender      The id of the group member that added us.
     * @return (state, The timestamp corresponding to the Create or Add Message that added us to the group.
     *This will be passed to the DcgkaProtocol.)
     */
    Pair<S, T> processWelcomeInfo(S state, OrderInfo welcomeInfo, IdentityKey sender);

    /**
     * After calling {@link Orderer#getNextOrderInfo} for an Add Message, but before calling
     * {@link Orderer#getNextOrderInfo} for any later messages, call this method
     * to get {@code welcomeInfo} to pass to the new group member's {@link Orderer#processWelcomeInfo}
     * method, so that they can learn the timestamp of the Add Message.  This will let the added user know
     * which messages are causally prior, concurrent, or causally later than its addition.  E.g., this method
     * could return a serialized version of our current internal vector clock.
     * <p>
     * This method is not used when creating the group.
     *
     * @param state The state to reference (immutably).
     * @return {@code welcomeInfo} for an added user.
     */
    OrderInfo getWelcomeInfo(S state);

    /**
     * {@code message}: As in {@link Orderer#queue}.
     * <p>
     * {@code sender}: As in {@link Orderer#queue}.
     * <p>
     * {@code causalInfo}: {@code message}'s timestamp, e.g., a vector clock.
     * <p>
     * {@code nextState}: the state to use if this message is processed successfully (i.e., it is
     * not a forgery).
     */
    class ReadyMessage<M, T, S extends State> {
        public final S nextState;
        public final M message;
        public final IdentityKey sender;
        public final T causalInfo;

        public ReadyMessage(S nextState, M message, IdentityKey sender, T causalInfo) {
            this.nextState = nextState;
            this.message = message;
            this.sender = sender;
            this.causalInfo = causalInfo;
        }
    }

    class OrderInfo extends ByteHolder {
        public OrderInfo(byte[] bytes) {
            super(bytes);
        }

        public static OrderInfo of(byte[] bytes) {
            return new OrderInfo(bytes);
        }
    }

    interface State {
    }
}
