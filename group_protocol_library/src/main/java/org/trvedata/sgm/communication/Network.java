package org.trvedata.sgm.communication;

public interface Network {
    void connect(final Client client, final String name);

    void send(final Client sender, final Object recipientIdentifier, final byte[] message);

    void broadcast(final Client sender, final byte[] message);

    String idToName(final Object identifier);

    int numClients();
}
