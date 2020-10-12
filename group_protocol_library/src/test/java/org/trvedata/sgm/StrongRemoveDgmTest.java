package org.trvedata.sgm;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Test;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.message.MessageId;
import org.trvedata.sgm.misc.Logger;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

public class StrongRemoveDgmTest {
    @Test
    public void testSet_initializationViewsCorrect() {
        ArrayList<IdentityKey> members = generateIdentityKeys(5);
        ArrayList<StrongRemoveDgm> sets = generateSets(members);
        assertAllViewsEqual(sets, members, members);
    }

    @Test
    public void testSet_simpleAddCorrect() {
        ArrayList<IdentityKey> members = generateIdentityKeys(5);
        ArrayList<StrongRemoveDgm> sets = generateSets(members);

        // members[0] adds a new member, everyone receives the add
        IdentityKey added = generateIdentityKeys(1).get(0);
        sets.add(StrongRemoveDgm.deserialize(sets.get(0).serialize().getLeft(), added).getLeft());
        MessageId messageId = new MessageId(members.get(0), 0);
        for (int i = 0; i < 6; i++) {
            sets.get(i).add(members.get(0), added, messageId);
        }

        // At this point, everything thinks they, the adder (members.get(0)), and added
        // have processed the add, while no one else has.
        ArrayList<IdentityKey> membersWithAdded = new ArrayList<>(members);
        membersWithAdded.add(added);
        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < 6; j++) {
                if (j == i) assertThat(compare(sets.get(i).queryWhole(), membersWithAdded)).isTrue();
                else {
                    if (j == 0 || j == 5) {
                        assertThat(compare(sets.get(i).queryView(membersWithAdded.get(j)), membersWithAdded)).isTrue();
                    } else assertThat(compare(sets.get(i).queryView(membersWithAdded.get(j)), members)).isTrue();
                }
            }
        }

        // Now have everyone ack the message.
        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < 6; j++) {
                if (j != i && j != 0 && j != 5) sets.get(i).ack(membersWithAdded.get(j), messageId);
            }
        }

        // Now check that every view is membersWithAdded.
        assertAllViewsEqual(sets, membersWithAdded, membersWithAdded);
    }

    @Test
    public void testSet_simpleRemoveCorrect() {
        ArrayList<IdentityKey> members = generateIdentityKeys(5);
        ArrayList<StrongRemoveDgm> sets = generateSets(members);

        // members[0] removes members[4], everyone but members[4] receives the remove
        MessageId messageId = new MessageId(members.get(0), 0);
        ArrayList<IdentityKey> removedList = new ArrayList<>();
        removedList.add(members.get(4));
        for (int i = 0; i < 4; i++) {
            sets.get(i).remove(members.get(0), removedList, messageId);
        }

        // At this point, everything thinks they and the adder (members.get(0))
        // have processed the add, while no one else has.
        ArrayList<IdentityKey> membersWithoutRemoved = new ArrayList<>(members);
        membersWithoutRemoved.remove(members.get(4));
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                if (j == i) assertThat(compare(sets.get(i).queryWhole(), membersWithoutRemoved)).isTrue();
                else {
                    if (j == 0) {
                        assertThat(compare(sets.get(i).queryView(members.get(j)), membersWithoutRemoved)).isTrue();
                    } else assertThat(compare(sets.get(i).queryView(members.get(j)), members)).isTrue();
                }
            }
        }

        // Now have everyone ack the message.
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                if (j != i && j != 0) sets.get(i).ack(members.get(j), messageId);
            }
        }

        // Now check that every view is membersWithAdded.
        sets.remove(4);
        assertAllViewsEqual(sets, membersWithoutRemoved, membersWithoutRemoved);
    }

    @Test
    public void testSet_totallyOrderedFuzzedMessagesCorrect() {
        TotallyOrderedTest test = new TotallyOrderedTest(new Random(123456));
        for (int i = 0; i < 100; i++) test.doOneTask();
    }

    private static class TotallyOrderedTest {
        ArrayList<IdentityKey> members = null;
        ArrayList<StrongRemoveDgm> sets = null;
        ArrayList<Integer> nextMessageNumbers = new ArrayList<>();
        Random random;

        TotallyOrderedTest(Random random) {
            this.random = random;
        }

        /**
         * Each call performs one random operation (add/remove, or creation
         * if not yet initialized).  The operations are totally
         * ordered, i.e., we deliver the message and acks to all members immediately.
         * The method ends by checking that everyone's views agree with the
         * directly computed set of members.
         */
        public void doOneTask() {
            if (members == null) {
                // Create the group
                int size = random.nextInt(20) + 1;
                Logger.i("group_protocol", "Creating group of size " + size);
                members = generateIdentityKeys(size);
                sets = generateSets(members);
                for (IdentityKey member : members) nextMessageNumbers.add(0);
            } else {
                // Randomly decide to add or remove.  Bias 2:1 towards adds since removes remove ~2 users
                // in expectation.
                if (random.nextInt(3) != 0) {
                    // A random user adds a new user.
                    int adderIndex = random.nextInt(members.size());
                    IdentityKey added = generateIdentityKeys(1).get(0);
                    Logger.i("group_protocol", "Add by " + members.get(adderIndex).hashCode() +
                            " of " + added.hashCode());
                    members.add(added);
                    sets.add(StrongRemoveDgm.deserialize(sets.get(adderIndex).serialize().getLeft(), added).getLeft());
                    nextMessageNumbers.add(0);

                    MessageId messageId = new MessageId(members.get(adderIndex), nextMessageNumbers.get(adderIndex));
                    nextMessageNumbers.set(adderIndex, nextMessageNumbers.get(adderIndex) + 1);
                    for (int i = 0; i < members.size(); i++) {
                        // Note this includes delivering the add to the just-added user
                        sets.get(i).add(members.get(adderIndex), added, messageId);
                    }

                    // Now have everyone ack the message.
                    for (int i = 0; i < members.size(); i++) {
                        for (int j = 0; j < members.size(); j++) {
                            if (j != i && j != adderIndex && j != (members.size() - 1)) {
                                sets.get(i).ack(members.get(j), messageId);
                            }
                        }
                    }
                } else {
                    // A random user removes a random subset of other users.  We definitely add 1,
                    // add another with probably 1/2, next probability 1/4, etc.
                    int removerIndex = random.nextInt(members.size());
                    IdentityKey remover = members.get(removerIndex);
                    MessageId messageId = new MessageId(members.get(removerIndex), nextMessageNumbers.get(removerIndex));
                    nextMessageNumbers.set(removerIndex, nextMessageNumbers.get(removerIndex) + 1);

                    ArrayList<IdentityKey> removedMembers = new ArrayList<>();
                    do {
                        if (members.size() == 1) break; // already removing everyone else
                        while (true) {
                            int newRemovedIndex = random.nextInt(members.size());
                            if (!members.get(newRemovedIndex).equals(remover)) {
                                removedMembers.add(members.get(newRemovedIndex));
                                members.remove(newRemovedIndex);
                                sets.remove(newRemovedIndex);
                                nextMessageNumbers.remove(newRemovedIndex);
                                break;
                            }
                        }
                    } while (random.nextInt(2) == 0); // stop adding users with probability 1/2
                    assert (members.contains(remover));
                    Logger.i("group_protocol", "Removal by " + remover.hashCode() + " of " +
                            toHashCodes(removedMembers));

                    // Deliver the message to all remaining users.
                    for (int i = 0; i < members.size(); i++) {
                        sets.get(i).remove(remover, removedMembers, messageId);
                    }

                    // Now have everyone ack the message.
                    for (int i = 0; i < members.size(); i++) {
                        for (int j = 0; j < members.size(); j++) {
                            if (j != i && !members.get(j).equals(remover)) {
                                sets.get(i).ack(members.get(j), messageId);
                            }
                        }
                    }
                }
            }

            Logger.i("group_protocol", "Current members: " + toHashCodes(members));

            // Assert that everyone's views all equal members.
            assertAllViewsEqual(sets, members, members);
        }
    }

    @Test
    public void testSet_concurrentRemovesBothOccur() {
        ArrayList<IdentityKey> members = generateIdentityKeys(3);
        StrongRemoveDgm set = new StrongRemoveDgm(members, members.get(0));
        MessageId remove1 = new MessageId(members.get(1), 0);
        set.remove(members.get(1), Collections.singleton(members.get(2)), remove1);
        MessageId remove2 = new MessageId(members.get(2), 0);
        set.remove(members.get(2), Collections.singleton(members.get(1)), remove2);

        assertThat(compare(set.queryWhole(), Collections.singleton(members.get(0)))).isTrue();
        assertThat(compare(set.queryView(members.get(1)), Arrays.asList(members.get(0), members.get(1)))).isTrue();
        assertThat(compare(set.queryView(members.get(2)), Arrays.asList(members.get(0), members.get(2)))).isTrue();
    }

    @Test
    public void testSet_addByRemovedUserDoesNotOccur() {
        ArrayList<IdentityKey> members = generateIdentityKeys(2);
        StrongRemoveDgm set = new StrongRemoveDgm(members, members.get(0));
        MessageId remove1 = new MessageId(members.get(0), 0);
        set.remove(members.get(0), Collections.singleton(members.get(1)), remove1);
        MessageId add1 = new MessageId(members.get(1), 0);
        members.add(generateIdentityKeys(1).get(0));
        set.add(members.get(1), members.get(2), add1);

        assertThat(compare(set.queryWhole(), Collections.singleton(members.get(0)))).isTrue();
        assertThat(compare(set.queryView(members.get(1)), members)).isTrue();
        assertThat(compare(set.queryView(members.get(2)), members)).isTrue();
    }

    @Test
    public void testSet_removeCancelsConcurrentAddByRemoved() {
        ArrayList<IdentityKey> members = generateIdentityKeys(3);
        StrongRemoveDgm set = new StrongRemoveDgm(members, members.get(0));
        MessageId add1 = new MessageId(members.get(1), 0);
        members.add(generateIdentityKeys(1).get(0));
        set.add(members.get(1), members.get(3), add1);
        MessageId remove1 = new MessageId(members.get(2), 0);
        set.remove(members.get(2), Collections.singleton(members.get(1)), remove1);

        assertThat(compare(set.queryWhole(), Arrays.asList(members.get(0), members.get(2)))).isTrue();
        assertThat(compare(set.queryView(members.get(2)), Arrays.asList(members.get(0), members.get(2)))).isTrue();
        assertThat(compare(set.queryView(members.get(1)), members)).isTrue();
        assertThat(compare(set.queryView(members.get(3)), members)).isTrue();
    }

    @Test
    public void testSet_removeDoesNotCancelAckedAddByRemoved() {
        ArrayList<IdentityKey> members = generateIdentityKeys(3);
        StrongRemoveDgm set = new StrongRemoveDgm(members, members.get(0));
        MessageId add1 = new MessageId(members.get(1), 0);
        members.add(generateIdentityKeys(1).get(0));
        set.add(members.get(1), members.get(3), add1);
        set.ack(members.get(2), add1);
        MessageId remove1 = new MessageId(members.get(2), 0);
        set.remove(members.get(2), Collections.singleton(members.get(1)), remove1);

        assertThat(compare(set.queryWhole(), Arrays.asList(members.get(0), members.get(2), members.get(3)))).isTrue();
        assertThat(compare(set.queryView(members.get(2)), Arrays.asList(members.get(0), members.get(2), members.get(3)))).isTrue();
        assertThat(compare(set.queryView(members.get(1)), members)).isTrue();
        assertThat(compare(set.queryView(members.get(3)), members)).isTrue();
    }

    @Test
    public void testSet_removeCancelsConcurrentTransitiveAddByRemoved() {
        ArrayList<IdentityKey> members = generateIdentityKeys(3);
        StrongRemoveDgm set = new StrongRemoveDgm(members, members.get(0));
        members.addAll(generateIdentityKeys(2));
        MessageId add1 = new MessageId(members.get(1), 0);
        set.add(members.get(1), members.get(3), add1);
        MessageId add2 = new MessageId(members.get(3), 0);
        set.add(members.get(3), members.get(4), add2);
        MessageId remove1 = new MessageId(members.get(2), 0);
        set.remove(members.get(2), Collections.singleton(members.get(1)), remove1);

        assertThat(compare(set.queryWhole(), Arrays.asList(members.get(0), members.get(2)))).isTrue();
        assertThat(compare(set.queryView(members.get(2)), Arrays.asList(members.get(0), members.get(2)))).isTrue();
        assertThat(compare(set.queryView(members.get(1)), members)).isTrue();
        assertThat(compare(set.queryView(members.get(3)), members)).isTrue();
        assertThat(compare(set.queryView(members.get(4)), members)).isTrue();
    }

    @Test
    public void testSet_randomCausalActionsCauseNoErrorsAndPrintsTranscript() {
        GenerateSetCausally gen = new GenerateSetCausally(new Random(1234), 10);
        for (int i = 0; i < 100; i++) gen.doOneTask(10, true);
    }

    @Test
    public void testSet_operationsCommuteInRandomState() {
        // TODO
    }

    /*@Test
    public void testSet_debugDeepCopyIsEqual() {
        GenerateSetCausally gen = new GenerateSetCausally(new Random(1234), 10);
        for (int i = 0; i < 100; i++) gen.doOneTask(5, false);
        MembershipSet copy = gen.set.debugDeepCopy(gen.set.getMyId());
        assertThat(gen.set.equals(copy)).isTrue();
    }*/

    @Test
    public void testSet_deserializedIsEqual() {
        GenerateSetCausally gen = new GenerateSetCausally(new Random(1234), 10);
        for (int i = 0; i < 100; i++) gen.doOneTask(5, false);
        StrongRemoveDgm copy = StrongRemoveDgm.deserialize(gen.set.serialize().getLeft(), gen.set.getMyId()).getLeft();
        assertThat(gen.set.equals(copy)).isTrue();
    }

    /**
     * Randomly applies operations to a MembershipSet simulating a causal non-total
     * delivery order.
     */
    private static class GenerateSetCausally {
        Random random;
        ArrayList<IdentityKey> members;
        HashMap<IdentityKey, HashMap<IdentityKey, Integer>> vvs = new HashMap<>();
        StrongRemoveDgm set;
        // Contains MessageId's and their version vectors.
        ArrayList<Pair<MessageId, HashMap<IdentityKey, Integer>>> messageVvs = new ArrayList<>();

        GenerateSetCausally(Random random, int initialNumMembers) {
            this.random = random;
            members = generateIdentityKeys(initialNumMembers);
            set = new StrongRemoveDgm(members, members.get(0));
            HashMap<IdentityKey, Integer> initialVv = new HashMap<>();
            for (IdentityKey member : members) initialVv.put(member, 0);
            for (IdentityKey member : members) {
                vvs.put(member, new HashMap<>(initialVv));
            }
            Logger.i("group_protocol", "Creating group of size " + initialNumMembers +
                    " with local member 0");
        }

        /**
         * Perform a random eligible operation (add, remove, or ack) on set.
         * The ratio of acks to adds/removes is roughly given by ackRatio.
         */
        void doOneTask(int ackRatio, boolean outputInfo) {
            IdentityKey actor = members.get(random.nextInt(members.size()));
            if (random.nextInt(ackRatio) != 0 && !actor.equals(set.getMyId())) {
                // Deliver a random eligible ack from actor, if one exists.
                ArrayList<Pair<MessageId, HashMap<IdentityKey, Integer>>> shuffledMessageVvs =
                        new ArrayList<>(messageVvs);
                Collections.shuffle(shuffledMessageVvs, random);
                for (Pair<MessageId, HashMap<IdentityKey, Integer>> messageVv : shuffledMessageVvs) {
                    // See if this ack is eligible for delivery, i.e., its vv is <= actor's
                    // vv in every coordinate except the author's, where it is one greater than
                    // actor's author coordinate.
                    boolean eligible = true;
                    for (Map.Entry<IdentityKey, Integer> messageVvEntry : messageVv.getRight().entrySet()) {
                        if (messageVvEntry.getKey().equals(messageVv.getLeft().author)) {
                            if (messageVvEntry.getValue() != vvs.get(actor).get(messageVvEntry.getKey()) + 1) {
                                eligible = false;
                                break;
                            }
                        } else {
                            if (messageVvEntry.getValue() > vvs.get(actor).get(messageVvEntry.getKey())) {
                                eligible = false;
                                break;
                            }
                        }
                    }
                    if (eligible) {
                        if (outputInfo) {
                            Logger.i("group_protocol", "Ack by " + indexString(actor) + " of " +
                                    indexString(messageVv.getLeft()));
                        }
                        // Deliver the ack
                        try {
                            set.ack(actor, messageVv.getLeft());
                        } catch (IllegalArgumentException exc) {
                            // This happens because we don't yet stop users from acking their own removal (see TODO below)
                            return;
                        }
                        // Adjust actor's vv
                        vvs.get(actor).put(messageVv.getLeft().author,
                                vvs.get(actor).get(messageVv.getLeft().author) + 1);
                        if (outputInfo) {
                            Logger.i("group_protocol", "Current members: " + indexString(set.queryWhole()));
                        }
                        return;
                    }
                }
                if (outputInfo) {
                    Logger.i("group_protocol", "No eligible acks for actor " + indexString(actor));
                }
            }

            // Otherwise, or if no ack was found:
            // Randomly decide to add or remove.  Bias 2:1 towards adds since removes remove ~2 users
            // in expectation.
            if (random.nextInt(3) != 0) {
                // A random user adds a new user.
                IdentityKey added = generateIdentityKeys(1).get(0);
                // To adjust vvs, actor increments their own index (self-delivery) and we copy their vv
                // to added.
                vvs.get(actor).put(actor, vvs.get(actor).get(actor) + 1);
                members.add(added);
                vvs.put(added, new HashMap<>(vvs.get(actor)));
                // Also update the local user's vv, since they get the add right away.
                vvs.get(set.getMyId()).put(actor, vvs.get(actor).get(actor));
                // Add 0s for the added user to everyone's vvs
                for (HashMap<IdentityKey, Integer> vv : vvs.values()) vv.put(added, 0);

                MessageId messageId = new MessageId(actor, vvs.get(actor).get(actor));
                if (outputInfo) {
                    Logger.i("group_protocol", "Add by " + indexString(actor) +
                            " of " + indexString(added) + " (" + indexString(messageId) + ")");
                }
                set.add(actor, added, messageId);
                messageVvs.add(Pair.of(messageId, new HashMap<>(vvs.get(actor))));
            } else {
                // A random user removes a random subset of other users.  We definitely add 1,
                // add another with probably 1/2, next probability 1/4, etc.
                vvs.get(actor).put(actor, vvs.get(actor).get(actor) + 1);
                // Also update the local user's vv, since they get the add right away.
                vvs.get(set.getMyId()).put(actor, vvs.get(actor).get(actor));

                ArrayList<IdentityKey> removed = new ArrayList<>();
                // Choose the users to remove.  We build removable in a roundabout way
                // to make sure its order is deterministic as a function of random.
                ArrayList<IdentityKey> removable = new ArrayList<>();
                HashSet<IdentityKey> removableUnordered = new HashSet<>(set.queryView(actor));
                for (IdentityKey member : members) {
                    if (removableUnordered.contains(member) && !actor.equals(member)
                            && !set.getMyId().equals(member)) removable.add(member);
                }
                do {
                    if (removable.isEmpty()) break; // already removing everyone else
                    removed.add(removable.remove(random.nextInt(removable.size())));
                } while (random.nextInt(2) == 0); // stop adding users with probability 1/2

                MessageId messageId = new MessageId(actor, vvs.get(actor).get(actor));
                if (outputInfo) {
                    Logger.i("group_protocol", "Removal by " + indexString(actor) + " of " +
                            indexString(removed) + " (" + indexString(messageId) + ")");
                }
                set.remove(actor, removed, messageId);
                messageVvs.add(Pair.of(messageId, new HashMap<>(vvs.get(actor))));
            }
            if (outputInfo) {
                Logger.i("group_protocol", "Current members: " + indexString(set.queryWhole()));
            }

            // TODO: exclude acks from users who shouldn't receive a message (e.g. because removed)?
            // Or code MembershipTest to tolerate such things, so the network layer doesn't have to
            // worry about it.

        }

        private String indexString(MessageId messageId) {
            return "(" + indexString(messageId.author) + ", " + messageId.number + ")";
        }

        private String indexString(IdentityKey id) {
            return "" + members.indexOf(id);
        }

        private String indexString(Collection<IdentityKey> ids) {
            StringBuilder ret = new StringBuilder("[");
            boolean first = true;
            for (int i = 0; i < members.size(); i++) {
                if (ids.contains(members.get(i))) {
                    if (first) first = false;
                    else ret.append(", ");
                    ret.append(i);
                }
            }
            ret.append("]");
            return ret.toString();
        }
    }


    private static ArrayList<IdentityKey> generateIdentityKeys(int number) {
        ArrayList<IdentityKey> ret = new ArrayList<>();
        for (int i = 0; i < number; i++) {
            ret.add(IdentityKey.generateKeyPair().getPublicKey());
        }
        return ret;
    }

    private static ArrayList<StrongRemoveDgm> generateSets(ArrayList<IdentityKey> members) {
        ArrayList<StrongRemoveDgm> sets = new ArrayList<>();
        for (int i = 0; i < members.size(); i++) {
            sets.add(new StrongRemoveDgm(members, members.get(i)));
        }
        return sets;
    }

    // Compare ignoring order.  Returns false if either input contains duplicates.
    private static <T, U> boolean compare(Collection<T> a, Collection<U> b) {
        HashSet<T> aSet = new HashSet<>(a);
        HashSet<U> bSet = new HashSet<>(b);
        if (aSet.size() != a.size()) return false;
        if (bSet.size() != b.size()) return false;
        return aSet.equals(bSet);
    }

    private static void assertAllViewsEqual(Collection<StrongRemoveDgm> sets, Collection<IdentityKey> members,
                                            Collection<IdentityKey> value) {
        for (StrongRemoveDgm set : sets) {
            assertThat(compare(set.queryWhole(), value)).isTrue();
            for (IdentityKey member : members) {
                assertThat(compare(set.queryView(member), value)).isTrue();
            }
        }
    }

    private static String toHashCodes(Collection<IdentityKey> ids) {
        StringBuilder ret = new StringBuilder("[");
        boolean first = true;
        for (IdentityKey id : ids) {
            if (first) first = false;
            else ret.append(", ");
            ret.append(id.hashCode());
        }
        ret.append("]");
        return ret.toString();
    }

    private static <T> T atIndex(Collection<T> collection, int index) {
        int i = 0;
        for (T element : collection) {
            if (i == index) return element;
            i++;
        }
        throw new IllegalArgumentException("Index out of bounds");
    }
}
