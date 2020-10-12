package org.trvedata.sgm.communication;

import org.apache.commons.lang3.tuple.Triple;

import java.util.ArrayDeque;

public class TotalOrderSimpleNetwork extends SimpleNetwork {
    private boolean isActive = false;
    private ArrayDeque<Triple<Client, Client, byte[]>> queuedMessages = new ArrayDeque<>(); // (sender, recipient, message)

    /**
     * Overrides broadcast to use a message queue and detect recursive calls, so that
     * message is sent to everyone before any response messages are sent.
     */
    @Override
    public void broadcast(final Client sender, final byte[] message) {
        for (Client client : mIdentifierToClient.values()) {
            if (client != sender) queuedMessages.add(Triple.of(sender, client, message));
        }
        if (!isActive) {
            // Prevent recursive calls from reaching this block
            isActive = true;
            while (!queuedMessages.isEmpty()) {
                Triple<Client, Client, byte[]> toSend = queuedMessages.pop();
                toSend.getMiddle().handleMessageFromNetwork(toSend.getLeft().getIdentifier(), toSend.getRight());
            }
            isActive = false;
        }
    }
}
