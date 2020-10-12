package org.trvedata.sgm.communication;

import org.trvedata.sgm.misc.Preconditions;

import java.util.HashMap;

/**
 * The network class connects a given set of {@link Client} members and allows message passing based on their identifiers.
 */
public class SimpleNetwork implements Network {

    protected final HashMap<Object, Client> mIdentifierToClient = new HashMap<>();
    protected final HashMap<Object, String> mIdentifierToName = new HashMap<>();

    public SimpleNetwork() {
    }

    /**
     * Connects a client with a given name to the network such that it can be resolved via its identifier.
     */
    @Override
    public void connect(final Client client, final String name) {
        mIdentifierToClient.put(client.getIdentifier(), client);
        mIdentifierToName.put(client.getIdentifier(), name);
    }

    /**
     * Sends a message from the given sender to a client that matches the `recipientIdentifier`.
     */
    @Override
    public void send(final Client sender, final Object recipientIdentifier, final byte[] message) {
        final Client recipient = mIdentifierToClient.get(recipientIdentifier);
        Preconditions.checkArgument(
                recipient != null,
                "The client with identifier " + recipientIdentifier + " is not connected to the network.");

        recipient.handleMessageFromNetwork(sender.getIdentifier(), message);
    }

    /**
     * Broadcasts a message to the whole group.  An implementation can override this method to do something
     * besides just call send on each member, e.g., ensure that the given message is sent to everyone
     * before any responses are sent.
     */
    @Override
    public void broadcast(final Client sender, final byte[] message) {
        for (Client client : mIdentifierToClient.values()) {
            if (!client.getIdentifier().equals(sender.getIdentifier())) {
                client.handleMessageFromNetwork(sender.getIdentifier(), message);
            }
        }
    }

    /**
     * Resolves a client's name from a given identifier. In case the client identifier is unknown, a human readable
     * explanation is returned.
     */
    @Override
    public String idToName(final Object identifier) {
        return mIdentifierToName.getOrDefault(identifier, "<unknown client>");
    }

    @Override
    public int numClients() {
        return mIdentifierToClient.size();
    }
}
