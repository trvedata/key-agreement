package org.trvedata.sgm.communication;

public abstract class Client {

    private Network mNetwork;
    protected String name;

    protected void init(final Network network, final String name) {
        mNetwork = network;
        mNetwork.connect(this, name);
        this.name = name;
    }

    protected void send(final Object recipientIdentifier, final byte[] message) {
        mNetwork.send(this, recipientIdentifier, message);
    }

    protected void broadcast(final byte[] message) {
        mNetwork.broadcast(this, message);
    }

    public String getName(final Object identifier) {
        if (mNetwork == null || identifier == null) return "<unknown>";
        return mNetwork.idToName(identifier);
    }

    public abstract Object getIdentifier();

    public abstract void handleMessageFromNetwork(final Object senderIdentifier, final byte[] message);

}
