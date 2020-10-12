package org.trvedata.sgm.communication;

import org.junit.Test;

import java.util.LinkedList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class SimpleNetworkClientTest {

    final byte[] TEST_MESSAGE_1 = "hello".getBytes();
    final byte[] TEST_MESSAGE_2 = "hallo".getBytes();
    final byte[] TEST_MESSAGE_3 = "hola".getBytes();

    @Test
    public void testNetwork_whenConnectingClients_nothingSpecialHappens() {
        final SimpleNetwork network = new SimpleNetwork();
        new TestClient(network, "alice");
        new TestClient(network, "bob");
    }

    @Test
    public void testNetwork_whenSendingMessages_thenArriveInOrder() {
        final SimpleNetwork network = new SimpleNetwork();
        final TestClient clientAlice = new TestClient(network, "alice");
        final TestClient clientBob = new TestClient(network, "bob");

        clientAlice.send("bob", TEST_MESSAGE_1);
        clientAlice.send("bob", TEST_MESSAGE_2);
        clientBob.send("alice", TEST_MESSAGE_3);

        assertThat(clientBob.getReceivedMessages()).containsExactly(TEST_MESSAGE_1, TEST_MESSAGE_2);
        assertThat(clientAlice.getReceivedMessages()).containsExactly(TEST_MESSAGE_3);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNetwork_whenSendingMessagesToUnknownRecipient_thenThrows() {
        final SimpleNetwork network = new SimpleNetwork();
        final TestClient clientAlice = new TestClient(network, "alice");

        clientAlice.send("bob", TEST_MESSAGE_1);
    }

    private static class TestClient extends Client {

        private final String name;
        private final List<byte[]> receivedMessages = new LinkedList<>();

        private TestClient(final SimpleNetwork network, final String name) {
            this.name = name;
            super.init(network, name);
        }

        @Override
        public Object getIdentifier() {
            return this.name;
        }

        @Override
        public void handleMessageFromNetwork(Object senderIdentifier, byte[] message) {
            receivedMessages.add(message);
        }

        public List<byte[]> getReceivedMessages() {
            return receivedMessages;
        }
    }

}
