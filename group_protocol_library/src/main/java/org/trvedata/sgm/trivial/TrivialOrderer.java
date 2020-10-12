package org.trvedata.sgm.trivial;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.trvedata.sgm.Orderer;
import org.trvedata.sgm.crypto.IdentityKey;

import java.util.ArrayDeque;
import java.util.Queue;

/**
 * Trivial implementation of {@link Orderer}, which fulfills all the
 * class's contracts but does not do any ordering, instead delivering messages immediately and
 * attaching no causal metadata.
 */
public class TrivialOrderer<M, T, I> implements Orderer<M, T, I, TrivialOrderer.State<M>> {

    @Override
    public State<M> queue(State<M> state, M message, IdentityKey sender, OrderInfo orderInfo) {
        Queue<Pair<M, IdentityKey>> newMessages = new ArrayDeque<>(state.messages);
        newMessages.add(Pair.of(message, sender));
        return new State<>(newMessages);
    }

    @Override
    public ReadyMessage<M, T, State<M>> getReadyMessage(State<M> state) {
        if (state.messages.isEmpty()) return null;
        else {
            Queue<Pair<M, IdentityKey>> newMessages = new ArrayDeque<>(state.messages);
            Pair<M, IdentityKey> message = newMessages.poll();
            return new ReadyMessage<>(new State<>(newMessages), message.getLeft(), message.getRight(), null);
        }
    }

    @Override
    public State<M> skipReadyMessage(State<M> state) {
        return getReadyMessage(state).nextState;
    }

    @Override
    public Triple<State<M>, OrderInfo, T> getNextOrderInfo(State<M> state, I dcgkaInput) {
        return Triple.of(state, OrderInfo.of(new byte[0]), null);
    }

    @Override
    public Pair<State<M>, T> processWelcomeInfo(State<M> state, OrderInfo welcomeInfo, IdentityKey sender) {
        return Pair.of(new State<>(new ArrayDeque<>()), null);
    }

    @Override
    public OrderInfo getWelcomeInfo(State<M> state) {
        return OrderInfo.of(new byte[0]);
    }

    public static class State<M> implements Orderer.State {
        private Queue<Pair<M, IdentityKey>> messages;

        private State(Queue<Pair<M, IdentityKey>> messages) {
            this.messages = messages;
        }

        public State() {
            this(new ArrayDeque<>());
        }
    }
}
