package org.trvedata.sgm;

import org.junit.Test;
import org.trvedata.sgm.communication.Network;
import org.trvedata.sgm.communication.TotalOrderSimpleNetwork;
import org.trvedata.sgm.crypto.InMemoryPreKeySource;
import org.trvedata.sgm.testhelper.PrintingDsgmListener;

import java.util.Arrays;

public class ModularDsgmTest {
    private void testGeneral_staticGroupTotallyOrdered_thenProcessedCorrectly(final DsgmClient.DgmClientImplementationConfiguration implementationConfiguration) {
        Network network = new TotalOrderSimpleNetwork(); // default Network with instant delivery
        DsgmClientFactory.DgmClientFactoryResult factoryResult = DsgmClientFactory.createClients(network,
                new InMemoryPreKeySource(), implementationConfiguration, "alice", "bob");
        DsgmClient alice = factoryResult.clients[0];
        DsgmClient bob = factoryResult.clients[1];
        alice.addListener(new PrintingDsgmListener("alice", factoryResult.identityKeyToName));
        bob.addListener(new PrintingDsgmListener("bob", factoryResult.identityKeyToName));

        // TODO: use a RecordingDgmListener to explicitly assert success, don't just rely on
        // the output of the PrintingDgmListeners
        alice.create(Arrays.asList(alice.getIdentifier(), bob.getIdentifier()));
        alice.send("Msg1 plain".getBytes());
        bob.send("Msg2 plain".getBytes());
        alice.update();
        bob.send("Msg3 plain".getBytes());
        alice.send("Msg4 plain".getBytes());
    }

    @Test
    public void testTrivial_staticGroupTotallyOrdered_thenProcessedCorrectly() {
        testGeneral_staticGroupTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.TRIVIAL, false, false, false));
    }

    @Test
    public void testFsae_staticGroupTotallyOrdered_thenProcessedCorrectly() {
        testGeneral_staticGroupTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.TRIVIAL, true, false, false));
    }

    @Test
    public void testSignature_staticGroupTotallyOrdered_thenProcessedCorrectly() {
        testGeneral_staticGroupTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.TRIVIAL, false, false, true));
    }

    @Test
    public void testOrderer_staticGroupTotallyOrdered_thenProcessedCorrectly() {
        testGeneral_staticGroupTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.TRIVIAL, false, true, false));
    }

    @Test
    public void testDcgka_staticGroupTotallyOrdered_thenProcessedCorrectly() {
        // Note FullDcgka requires AckOrderer to function
        testGeneral_staticGroupTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.FULL, false, true, false));
    }

    @Test
    public void testFull_staticGroupTotallyOrdered_thenProcessedCorrectly() {
        testGeneral_staticGroupTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.FULL, true, true, true));
    }


    /**
     * For the configuration, AckOrderer is required so the added user ignores the initial messages.
     */
    private void testGeneral_addTotallyOrdered_thenProcessedCorrectly(DsgmClient.DgmClientImplementationConfiguration implementationConfiguration) {
        Network network = new TotalOrderSimpleNetwork();
        DsgmClientFactory.DgmClientFactoryResult factoryResult = DsgmClientFactory.createClients(network,
                new InMemoryPreKeySource(), implementationConfiguration, "alice", "bob", "charlie");
        DsgmClient alice = factoryResult.clients[0];
        DsgmClient bob = factoryResult.clients[1];
        DsgmClient charlie = factoryResult.clients[2];
        alice.addListener(new PrintingDsgmListener("alice", factoryResult.identityKeyToName));
        bob.addListener(new PrintingDsgmListener("bob", factoryResult.identityKeyToName));
        charlie.addListener(new PrintingDsgmListener("charlie", factoryResult.identityKeyToName));

        // TODO: use a RecordingDgmListener to explicitly assert success, don't just rely on
        // the output of the PrintingDgmListeners
        alice.create(Arrays.asList(alice.getIdentifier(), bob.getIdentifier()));
        alice.send("Msg1 plain".getBytes());
        bob.send("Msg2 plain".getBytes());
        alice.update();
        bob.send("Msg3 plain".getBytes());
        alice.send("Msg4 plain".getBytes());

        bob.add(charlie.getIdentifier());
        charlie.send("Msg from Charlie 1".getBytes());
        alice.send("Msg to Charlie 1".getBytes());
        bob.send("Msg to Charlie 2".getBytes());

        bob.update();
        charlie.send("Msg from Charlie 2".getBytes());
        alice.send("Msg to Charlie 3".getBytes());
        bob.send("Msg to Charlie 4".getBytes());

        charlie.update();
        charlie.send("Msg from Charlie 3".getBytes());
        alice.send("Msg to Charlie 5".getBytes());
        bob.send("Msg to Charlie 6".getBytes());
    }

    @Test
    public void testTrivial_addTotallyOrdered_thenProcessedCorrectly() {
        testGeneral_addTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.TRIVIAL, false, true, false));
    }

    @Test
    public void testFsae_addTotallyOrdered_thenProcessedCorrectly() {
        testGeneral_addTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.TRIVIAL, true, true, false));
    }

    @Test
    public void testOrderer_addTotallyOrdered_thenProcessedCorrectly() {
        testGeneral_addTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.TRIVIAL, false, true, true));
    }

    @Test
    public void testDcgka_addTotallyOrdered_thenProcessedCorrectly() {
        testGeneral_addTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.FULL, false, true, false));
    }

    @Test
    public void testFull_addTotallyOrdered_thenProcessedCorrectly() {
        testGeneral_addTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.FULL, true, true, true));
    }

    /**
     * For the configuration, AckOrderer is required so the added user ignores the initial messages.
     */
    private void testGeneral_removeTotallyOrdered_thenProcessedCorrectly(DsgmClient.DgmClientImplementationConfiguration implementationConfiguration) {
        Network network = new TotalOrderSimpleNetwork();
        DsgmClientFactory.DgmClientFactoryResult factoryResult = DsgmClientFactory.createClients(network,
                new InMemoryPreKeySource(), implementationConfiguration, "alice", "bob", "charlie");
        DsgmClient alice = factoryResult.clients[0];
        DsgmClient bob = factoryResult.clients[1];
        DsgmClient charlie = factoryResult.clients[2];
        alice.addListener(new PrintingDsgmListener("alice", factoryResult.identityKeyToName));
        bob.addListener(new PrintingDsgmListener("bob", factoryResult.identityKeyToName));
        charlie.addListener(new PrintingDsgmListener("charlie", factoryResult.identityKeyToName));

        // TODO: use a RecordingDgmListener to explicitly assert success, don't just rely on
        // the output of the PrintingDgmListeners
        alice.create(Arrays.asList(alice.getIdentifier(), bob.getIdentifier(), charlie.getIdentifier()));
        alice.send("Msg1 plain".getBytes());
        bob.send("Msg2 plain".getBytes());
        charlie.send("Msg3 plain".getBytes());
        charlie.update();
        bob.send("Msg4 plain".getBytes());
        alice.send("Msg5 plain".getBytes());
        charlie.send("Msg6 plain".getBytes());

        bob.remove(charlie.getIdentifier());
        alice.send("Msg after remove 1".getBytes());
        bob.send("Msg after remove 2".getBytes());

        bob.update();
        alice.send("Msg after remove 3".getBytes());
        bob.send("Msg after remove 4".getBytes());

        alice.update();
        alice.send("Msg after remove 5".getBytes());
        bob.send("Msg after remove 6".getBytes());
    }

    @Test
    public void testTrivial_removeTotallyOrdered_thenProcessedCorrectly() {
        testGeneral_removeTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.TRIVIAL, false, true, false));
    }

    @Test
    public void testFsae_removeTotallyOrdered_thenProcessedCorrectly() {
        testGeneral_removeTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.TRIVIAL, true, true, false));
    }

    @Test
    public void testOrderer_removeTotallyOrdered_thenProcessedCorrectly() {
        testGeneral_removeTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.TRIVIAL, false, true, true));
    }

    @Test
    public void testDcgka_removeTotallyOrdered_thenProcessedCorrectly() {
        testGeneral_removeTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.FULL, false, true, false));
    }

    @Test
    public void testFull_removeTotallyOrdered_thenProcessedCorrectly() {
        testGeneral_removeTotallyOrdered_thenProcessedCorrectly(
                new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.FULL, true, true, true));
    }




    /*

    static ArrayList<Integer> hashCodes(Collection<? extends Object> values) {
        ArrayList<Integer> hashCodes = new ArrayList<>();
        for (Object value : values) {
            hashCodes.add(value.hashCode());
        }
        return hashCodes;
    }

    @Test
    public void testTrivialProtocol_whenTotallyOrdered_thenProcessedCorrectly() {
        final MutableBoolean aliceSuccess = new MutableBoolean();
        final MutableBoolean bobSuccess = new MutableBoolean();
        final BooleanListener aliceListener = new BooleanListener(aliceSuccess);
        final BooleanListener bobListener = new BooleanListener(bobSuccess);
        final ModularDgm<Object> alice = ModularDgm.getTrivialDgm(KeyHelper.generateIdentityKeyPair(), aliceListener);
        final ModularDgm<Object> bob = ModularDgm.getTrivialDgm(KeyHelper.generateIdentityKeyPair(), bobListener);
        final HashSet<IdentityKey> group = new HashSet<>();
        group.add(alice.getId());
        group.add(bob.getId());
        Logger.i("ModularDgmTest", "Alice: " + alice.getId().hashCode() + ", bob: " +
                bob.getId().hashCode());

        final byte[] welcome = alice.create(group);
        assertThat(alice.getMembers()).isEqualTo(group);

        bobSuccess.setFalse();
        bob.process(welcome);
        assertThat(bobSuccess.isTrue()).isTrue();
        assertThat(bob.getMembers()).isEqualTo(group);

        final byte[] msg1 = alice.send("Msg1 plain".getBytes());
        bobSuccess.setFalse();
        bob.process(msg1);
        assertThat(bobSuccess.isTrue()).isTrue();

        assertThat(bobListener.responses.size()).isEqualTo(1);
        byte[] ack1 = bobListener.responses.get(0);
        bobListener.responses.clear();
        //aliceSuccess.setFalse();
        alice.process(ack1);
        //assertThat(aliceSuccess.isTrue()).isTrue();

        final byte[] msg2 = bob.send("Msg2 plain".getBytes());
        aliceSuccess.setFalse();
        alice.process(msg2);
        assertThat(aliceSuccess.isTrue()).isTrue();

        final byte[] update = alice.update();
        bobSuccess.setFalse();
        bob.process(update);
        assertThat(bobSuccess.isTrue()).isTrue();

        assertThat(bobListener.responses.size()).isEqualTo(1);
        byte[] ack2 = bobListener.responses.get(0);
        bobListener.responses.clear();
        //aliceSuccess.setFalse();
        alice.process(ack2);
        //assertThat(aliceSuccess.isTrue()).isTrue();

        final byte[] msg3 = bob.send("Msg3 plain".getBytes());
        aliceSuccess.setFalse();
        alice.process(msg3);
        assertThat(aliceSuccess.isTrue()).isTrue();

        final byte[] msg4 = alice.send("Msg4 plain".getBytes());
        bobSuccess.setFalse();
        bob.process(msg4);
        assertThat(bobSuccess.isTrue()).isTrue();
    }

    /* // TODO: rewrite for ModularDgm
    // [W] GroupProtocol: Ack Message processed before its target: 0 >= 0
    // [W] GroupProtocol: Ack Message processed before its target: 2 >= 1
    @Ignore
    @Test
    public void testProtocol_whenInconsistentButCausalOrdering_thenProcessedCorrectly() {
        final Network network = new Network();
        final DczkaClient[] clients = DczkaClientFactory.createClients(network, "Alice", "Bob", "Charlie");

        final GroupProtocol alice = clients[0].getProtocol();
        final GroupProtocol bob = clients[1].getProtocol();
        final GroupProtocol charlie = clients[2].getProtocol();

        final ArrayList<IdentityKey> otherMembers = new ArrayList<>();
        otherMembers.add(bob.getPublicKey());
        otherMembers.add(charlie.getPublicKey());

        HashMap<IdentityKey, byte[]> init = alice.generateInitMessage(otherMembers);

        final HashSet<IdentityKey> identityKeysBob =
                bob.processInitMessage(init.get(bob.getPublicKey()), alice.getPublicKey());
        assertThat(identityKeysBob).contains(alice.getPublicKey());
        assertThat(identityKeysBob).contains(bob.getPublicKey());
        assertThat(identityKeysBob).contains(charlie.getPublicKey());

        final HashSet<IdentityKey> identityKeysCharlie =
                charlie.processInitMessage(init.get(charlie.getPublicKey()), alice.getPublicKey());
        assertThat(identityKeysCharlie).contains(alice.getPublicKey());
        assertThat(identityKeysCharlie).contains(bob.getPublicKey());
        assertThat(identityKeysCharlie).contains(charlie.getPublicKey());

        final byte[] msg1 = bob.generateApplicationMessage("Msg1 plain".getBytes(), "Msg1 AD".getBytes());
        assertThat(alice.processBroadcastMessageCausal(msg1)).isTrue();

        final byte[] msg2 = charlie.generateApplicationMessage("Msg2 plain".getBytes(), "Msg2 AD".getBytes());
        assertThat(alice.processBroadcastMessageCausal(msg2)).isTrue();
        assertThat(bob.processBroadcastMessageCausal(msg2)).isTrue();
        assertThat(charlie.processBroadcastMessageCausal(msg1)).isTrue(); // intentionally here

        final HashMap<IdentityKey, byte[]> update1 = alice.generateUpdateMessage();
        assertThat(bob.processPairwiseMessageCausal(update1.get(bob.getPublicKey()), alice.getPublicKey())).isTrue();
        assertThat(charlie.processPairwiseMessageCausal(update1.get(charlie.getPublicKey()), alice.getPublicKey())).isTrue();

        final HashMap<IdentityKey, byte[]> update2 = bob.generateUpdateMessage();
        assertThat(alice.processPairwiseMessageCausal(update2.get(alice.getPublicKey()), bob.getPublicKey())).isTrue();
        assertThat(charlie.processPairwiseMessageCausal(update2.get(charlie.getPublicKey()), bob.getPublicKey())).isTrue();

        final byte[] msg3 = alice.generateApplicationMessage("Msg3 plain".getBytes(), "Msg3 AD".getBytes());
        assertThat(charlie.processBroadcastMessageCausal(msg3)).isTrue();
        assertThat(bob.processBroadcastMessageCausal(msg3)).isTrue();

        final byte[] msg4 = bob.generateApplicationMessage("Msg4 plain".getBytes(), "Msg4 AD".getBytes());
        assertThat(charlie.processBroadcastMessageCausal(msg4)).isTrue();
        assertThat(alice.processBroadcastMessageCausal(msg4)).isTrue();
    }*/

}
