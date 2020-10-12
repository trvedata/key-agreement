package org.trvedata.sgm;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.IteratorUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.thrift.TException;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.message.MemberInfoStruct;
import org.trvedata.sgm.message.MembershipSetStruct;
import org.trvedata.sgm.message.MessageId;
import org.trvedata.sgm.message.RemoveInfoStruct;
import org.trvedata.sgm.misc.Utils;

import java.nio.ByteBuffer;
import java.util.*;

public class StrongRemoveDgm {

    private HashMap<IdentityKey, MemberInfo> members;
    private HashMap<IdentityKey, MemberInfo> removedMembers; // tombstone map
    private IdentityKey myId;
    private HashMap<MessageId, MemberInfo> addsById;
    private HashMap<MessageId, RemoveInfo> removesById;

    public StrongRemoveDgm(Collection<IdentityKey> initialMembers, IdentityKey myId) {
        this.myId = myId;
        members = new HashMap<>();
        removedMembers = new HashMap<>();
        addsById = new HashMap<>();
        removesById = new HashMap<>();
        for (IdentityKey member : initialMembers) {
            members.put(member, new MemberInfo(member, null, initialMembers));
        }
    }

    public static StrongRemoveDgm empty(IdentityKey myId) {
        return new StrongRemoveDgm(Collections.emptyList(), myId);
    }

    public IdentityKey getMyId() {
        return myId;
    }

    /**
     * Restriction: a user can only be added to a group once.
     * Returns true if the add was immediately cancelled by a concurrent remove
     * that we have already processed.
     */
    public boolean add(IdentityKey adder, IdentityKey added, MessageId messageId) {
        boolean removedByConcurrency;
        MemberInfo addedInfo = new MemberInfo(added, adder);
        addedInfo.acks.add(adder);
        addedInfo.acks.add(added);
        addedInfo.acks.add(myId);// might equal added or adder; OK b/c acks is a HashSet
        if (members.get(adder) != null) {
            // adder is still a group member, so this add sticks
            removedByConcurrency = false;
            members.put(added, addedInfo);
        } else {
            // adder has been removed, necessarily by remove messages concurrent to this
            // add message.  All the remove messages removing adder get credit for
            // removing added as well.
            removedByConcurrency = true;
            MemberInfo adderInfo = removedMembers.get(adder);
            if (adderInfo == null) throw new IllegalArgumentException("Unrecognized adder");
            for (RemoveInfo removeInfo : adderInfo.removeMessages) {
                removeInfo.removedUsers.add(added);
                addedInfo.removeMessages.add(removeInfo);
            }
            removedMembers.put(added, addedInfo);
        }
        // added has the same acks as adder
        for (MemberInfo memberInfo : members.values()) {
            if (memberInfo.acks.contains(adder)) memberInfo.acks.add(added);
        }
        for (MemberInfo memberInfo : removedMembers.values()) {
            if (memberInfo.acks.contains(adder)) memberInfo.acks.add(added);
        }
        for (RemoveInfo removeInfo : removesById.values()) {
            if (removeInfo.acks.contains(adder)) removeInfo.acks.add(added);
        }

        addsById.put(messageId, addedInfo);
        return removedByConcurrency;
    }

    /**
     * Returns the list of group members who were removed by this Remove Message,
     * i.e., the delta between the resulting list of members and the original list
     * of members.  This may exclude some members in removed because they were
     * already removed, and it may include extra members that were removed by concurrency.
     */
    public ArrayList<IdentityKey> remove(IdentityKey remover, Collection<IdentityKey> removed,
                                         MessageId messageId) {
        ArrayList<IdentityKey> returnValue = new ArrayList<>();
        RemoveInfo removeInfo = new RemoveInfo(removed);
        removeInfo.acks.add(remover);
        removeInfo.acks.add(myId);// might equal remover; OK b/c acks is a HashSet
        // Remove the users in removed (if needed) and mark them as removed by this message
        for (IdentityKey oneRemoved : removed) {
            MemberInfo memberInfo = members.remove(oneRemoved);
            if (memberInfo != null) {
                removedMembers.put(oneRemoved, memberInfo);
                returnValue.add(oneRemoved);
            } else {
                // oneRemoved has already been removed
                memberInfo = removedMembers.get(oneRemoved);
                if (memberInfo == null) {
                    throw new IllegalArgumentException("Unrecognized target of removal: " + oneRemoved.hashCode());
                }
            }
            memberInfo.removeMessages.add(removeInfo);
        }

        // If a removed user performed an add concurrent to this message (i.e., not yet ack'd by
        // remover), then the user added by that message is also considered removed by this
        // message.  This loop searches for such adds and removes their target.  Since
        // users removed in this fashion may themselves have added users, we have to apply this
        // rule repeatedly until it stops making progress.
        // TODO: can replace with a single pass in causal order
        boolean madeProgress;
        do {
            madeProgress = false;
            // Loop through current members, removing them like above if needed.
            Iterator<Map.Entry<IdentityKey, MemberInfo>> iterator = members.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<IdentityKey, MemberInfo> entry = iterator.next();
                if (removeInfo.removedUsers.contains(entry.getValue().adder) &&
                        !entry.getValue().acks.contains(remover)) {
                    // entry.getKey() is removed by this remove message
                    returnValue.add(entry.getKey());
                    iterator.remove(); // remove from members
                    removedMembers.put(entry.getKey(), entry.getValue());
                    entry.getValue().removeMessages.add(removeInfo);
                    removeInfo.removedUsers.add(entry.getKey());
                    madeProgress = true;
                }
            }
            // Loop through already removed users, adding this message to their list of
            // remove messages if it applies.
            for (Map.Entry<IdentityKey, MemberInfo> entry : removedMembers.entrySet()) {
                if (removeInfo.removedUsers.contains(entry.getValue().adder) &&
                        !entry.getValue().acks.contains(remover) &&
                        !entry.getValue().removeMessages.contains(removeInfo)) {
                    // entry.getKey() is re-removed by this remove message
                    entry.getValue().removeMessages.add(removeInfo);
                    removeInfo.removedUsers.add(entry.getKey());
                    madeProgress = true;
                }
            }

        } while (madeProgress);

        removesById.put(messageId, removeInfo);
        return returnValue;
    }

    /**
     * Note added users do not ack their own add.
     * This will throw an IllegalArgumentException if a user acks a message that removed them.
     */
    public void ack(IdentityKey acker, MessageId messageId) {
        MemberInfo add = addsById.get(messageId);
        if (add != null) {
            if (!add.acks.add(acker)) {
                // Don't complain if its the added user acking themselves (for real this time, as opposed to
                // the implicit ack that they give just from being added).
                if (!add.id.equals(acker)) {
                    throw new IllegalArgumentException("Already ack'd: " + messageId);
                }
            }
        } else {
            RemoveInfo remove = removesById.get(messageId);
            if (remove != null) {
                if (!remove.acks.add(acker)) {
                    throw new IllegalArgumentException("Already ack'd: " + messageId);
                }
                if (remove.removedUsers.contains(acker)) {
                    throw new IllegalArgumentException("Acking their own removal: " + acker.hashCode() + ", " +
                            messageId);
                }
            } else {
                throw new IllegalArgumentException("Ack'd message not recognized: " + messageId);
            }
        }
    }

    public HashSet<IdentityKey> queryWhole() {
        return new HashSet<>(members.keySet());
    }

    public HashSet<IdentityKey> queryWholeWithoutMe() {
        final HashSet<IdentityKey> set = new HashSet<>(members.keySet());
        set.remove(myId);
        return set;
    }

    public HashSet<IdentityKey> queryView(IdentityKey viewer) {
        if (viewer.equals(myId)) return queryWhole();

        HashSet<IdentityKey> view = new HashSet<>();
        // Include current members whose add was acked by viewer
        for (Map.Entry<IdentityKey, MemberInfo> entry : members.entrySet()) {
            if (entry.getValue().acks.contains(viewer)) view.add(entry.getKey());
        }
        // Also include removed members, none of whose removes have been acked by viewer
        for (Map.Entry<IdentityKey, MemberInfo> entry : removedMembers.entrySet()) {
            boolean anyAcked = false;
            for (RemoveInfo removeInfo : entry.getValue().removeMessages) {
                if (removeInfo.acks.contains(viewer)) {
                    anyAcked = true;
                    break;
                }
            }
            if (!anyAcked) view.add(entry.getKey());
        }
        return view;
    }

    public boolean isAdd(MessageId messageId) {
        return addsById.containsKey(messageId);
    }

    public boolean isRemove(MessageId messageId) {
        return removesById.containsKey(messageId);
    }

    /**
     * Returns the set of all members (or removed members) who have
     * ack'd the given message.
     *
     * @throws IllegalArgumentException - if messageId is not the MessageId
     *                                  of a known Add or Remove Message.
     */
    public Set<IdentityKey> getAcks(MessageId messageId) {
        MemberInfo addInfo = addsById.get(messageId);
        if (addInfo != null) {
            return Collections.unmodifiableSet(addInfo.acks);
        } else {
            RemoveInfo removeInfo = removesById.get(messageId);
            if (removeInfo != null) {
                return Collections.unmodifiableSet(removeInfo.acks);
            } else {
                throw new IllegalArgumentException("Unrecognized MessageId: " + messageId);
            }
        }
    }

    // Return a collection containing all current members and removed (tombstoned) members.
    public Collection<IdentityKey> getMembersAndRemovedMembers() {
        return CollectionUtils.union(members.keySet(), removedMembers.keySet());
    }

    /**
     * Serializes this object (first coordinate of the return value).  The second
     * coordinate of the return value gives an ordering on all current and former
     * group members; the same ordering will be returned by deserialize.  Thus it can be
     * used to store extra information for each member, such as the entries of
     * a version vector, as a list instead of a map from IdentityKey's, with a list
     * entry corresponding to the IdentityKey with the same index.
     * TODO: just use the canonical order?
     */
    public Pair<byte[], ArrayList<IdentityKey>> serialize() {
        // Assign indices to members and removedMembers
        HashMap<IdentityKey, Integer> memberIndices = new HashMap<>();
        ArrayList<IdentityKey> membersByIndex = new ArrayList<>();
        int i = 0;
        Iterator<IdentityKey> allMembersIterator =
                IteratorUtils.chainedIterator(members.keySet().iterator(), removedMembers.keySet().iterator());
        while (allMembersIterator.hasNext()) {
            IdentityKey member = allMembersIterator.next();
            memberIndices.put(member, i);
            membersByIndex.add(member);
            i++;
        }

        // Serialize RemoveInfo's and assign them indices
        ArrayList<RemoveInfoStruct> removeInfoStructs = new ArrayList<>();
        IdentityHashMap<RemoveInfo, Integer> removeInfoIndices = new IdentityHashMap<>();
        i = 0;
        for (Map.Entry<MessageId, RemoveInfo> removeEntry : removesById.entrySet()) {
            HashSet<Integer> removedUsers = new HashSet<>();
            for (IdentityKey removedUser : removeEntry.getValue().removedUsers) {
                removedUsers.add(memberIndices.get(removedUser));
            }
            HashSet<Integer> acks = new HashSet<>();
            for (IdentityKey ack : removeEntry.getValue().acks) {
                acks.add(memberIndices.get(ack));
            }
            removeInfoStructs.add(new RemoveInfoStruct(memberIndices.get(removeEntry.getKey().author),
                    removeEntry.getKey().number, removedUsers, acks));
            removeInfoIndices.put(removeEntry.getValue(), i);
            i++;
        }

        // Serialize MemberInfo's
        MemberInfoStruct[] memberInfoStructs = new MemberInfoStruct[members.size() + removedMembers.size()];
        IdentityHashMap<MemberInfo, MemberInfoStruct> structsByMemberInfo = new IdentityHashMap<>();
        Iterator<Map.Entry<IdentityKey, MemberInfo>> iterator =
                IteratorUtils.chainedIterator(members.entrySet().iterator(), removedMembers.entrySet().iterator());
        while (iterator.hasNext()) {
            Map.Entry<IdentityKey, MemberInfo> memberEntry = iterator.next();
            ArrayList<Integer> removeMessages = new ArrayList<>();
            for (RemoveInfo removeInfo : memberEntry.getValue().removeMessages) {
                removeMessages.add(removeInfoIndices.get(removeInfo));
            }
            HashSet<Integer> acks = new HashSet<>();
            for (IdentityKey ack : memberEntry.getValue().acks) {
                acks.add(memberIndices.get(ack));
            }
            MemberInfoStruct struct = new MemberInfoStruct(ByteBuffer.wrap(memberEntry.getKey().serialize()),
                    removeMessages, acks);
            memberInfoStructs[memberIndices.get(memberEntry.getKey())] = struct;
            structsByMemberInfo.put(memberEntry.getValue(), struct);
        }
        // Also add MessageId's to the MemberInfoStruct's for non-initial members
        for (Map.Entry<MessageId, MemberInfo> addEntry : addsById.entrySet()) {
            MemberInfoStruct struct = structsByMemberInfo.get(addEntry.getValue());
            struct.setAdder(memberIndices.get(addEntry.getKey().author));
            struct.setMessageNumber(addEntry.getKey().number);
        }

        // Final result
        return Pair.of(Utils.serialize(
                new MembershipSetStruct(Arrays.asList(memberInfoStructs), removeInfoStructs)),
                membersByIndex);
    }

    /**
     * Given the byte[] from an output of serialize, returns a copy of the
     * serialized MembershipSet, except with myId replaced by the given value.
     * The second coordinate of the output is a copy of
     * the second coordinate output by serialize.
     */
    public static Pair<StrongRemoveDgm, ArrayList<IdentityKey>> deserialize(
            byte[] serialized, IdentityKey myId) {
        StrongRemoveDgm set = new StrongRemoveDgm(Collections.emptyList(), myId);

        MembershipSetStruct setStruct = new MembershipSetStruct();
        try {
            Utils.deserialize(setStruct, serialized);
        } catch (TException exc) {
            throw new IllegalArgumentException("Thrift deserialization error: " + exc);
        }

        // Get the mapping from indices to IdentityKey's
        ArrayList<IdentityKey> idsByIndex = new ArrayList<>();
        for (MemberInfoStruct memberStruct : setStruct.getMembersAndRemovedMembers()) {
            try {
                idsByIndex.add(new IdentityKey(memberStruct.getId()));
            } catch (IllegalArgumentException exc) {
                throw new IllegalArgumentException("IdentityKey deserialization error: " + exc);
            }
        }

        // Deserialize RemoveInfoStruct's and get their index mapping.
        ArrayList<RemoveInfo> removesByIndex = new ArrayList<>();
        for (RemoveInfoStruct removeStruct : setStruct.getRemoveInfos()) {
            RemoveInfo removeInfo = new RemoveInfo(Collections.emptyList());
            for (int removedIndex : removeStruct.getRemovedUsers()) {
                removeInfo.removedUsers.add(idsByIndex.get(removedIndex));
            }
            for (int ackIndex : removeStruct.getAcks()) {
                removeInfo.acks.add(idsByIndex.get(ackIndex));
            }
            set.removesById.put(new MessageId(idsByIndex.get(removeStruct.getRemover()),
                    removeStruct.getMessageNumber()), removeInfo);
            removesByIndex.add(removeInfo);
        }

        // Deserialize MemberInfoStruct's
        int i = 0;
        for (MemberInfoStruct memberStruct : setStruct.getMembersAndRemovedMembers()) {
            MemberInfo memberInfo = new MemberInfo(idsByIndex.get(i), null);
            if (memberStruct.isSetAdder()) {
                memberInfo.adder = idsByIndex.get(memberStruct.getAdder());
                set.addsById.put(new MessageId(memberInfo.adder, memberStruct.getMessageNumber()),
                        memberInfo);
            }
            for (int removeIndex : memberStruct.getRemoveMessages()) {
                memberInfo.removeMessages.add(removesByIndex.get(removeIndex));
            }
            for (int ackIndex : memberStruct.getAcks()) {
                memberInfo.acks.add(idsByIndex.get(ackIndex));
            }
            if (memberInfo.removeMessages.isEmpty()) set.members.put(idsByIndex.get(i), memberInfo);
            else set.removedMembers.put(idsByIndex.get(i), memberInfo);
            i++;
        }

        return Pair.of(set, idsByIndex);
    }

    /*// Method for temporary testing purposes which makes a deep copy of this class.  In the future,
    // this ability will be supported by using serialize() + the deserializing constructor.
    public MembershipSet debugDeepCopy(IdentityKey newMyId) {
        MembershipSet other = new MembershipSet(new ArrayList<>(), newMyId);

        HashMap<RemoveInfo, RemoveInfo> removeInfoMap = new HashMap<>();
        for (Map.Entry<MessageId, RemoveInfo> entry : removesById.entrySet()) {
            RemoveInfo copy = new RemoveInfo(entry.getValue().removedUsers);
            copy.acks = new HashSet<>(entry.getValue().acks);
            removeInfoMap.put(entry.getValue(), copy);
            other.removesById.put(entry.getKey(), copy);
        }
        HashMap<MemberInfo, MemberInfo> memberInfoMap = new HashMap<>();
        for (Map.Entry<IdentityKey, MemberInfo> entry : members.entrySet()) {
            MemberInfo copy = debugMemberInfoDeepCopy(entry.getValue(), removeInfoMap);
            memberInfoMap.put(entry.getValue(), copy);
            other.members.put(entry.getKey(), copy);
        }
        for (Map.Entry<IdentityKey, MemberInfo> entry : removedMembers.entrySet()) {
            MemberInfo copy = debugMemberInfoDeepCopy(entry.getValue(), removeInfoMap);
            memberInfoMap.put(entry.getValue(), copy);
            other.removedMembers.put(entry.getKey(), copy);
        }
        for (Map.Entry<MessageId, MemberInfo> entry : addsById.entrySet()) {
            other.addsById.put(entry.getKey(), memberInfoMap.get(entry.getValue()));
        }

        return other;
    }

    private MemberInfo debugMemberInfoDeepCopy(MemberInfo original, HashMap<RemoveInfo, RemoveInfo> removeInfoMap) {
        MemberInfo copy = new MemberInfo(original.id, original.adder, original.acks);
        for (RemoveInfo originalRemoveInfo : original.removeMessages) {
            copy.removeMessages.add(removeInfoMap.get(originalRemoveInfo));
        }
        return copy;
    }*/

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StrongRemoveDgm that = (StrongRemoveDgm) o;
        return members.equals(that.members) &&
                removedMembers.equals(that.removedMembers) &&
                myId.equals(that.myId) &&
                addsById.equals(that.addsById) &&
                removesById.equals(that.removesById);
    }

    @Override
    public int hashCode() {
        return Objects.hash(members, removedMembers, myId, addsById, removesById);
    }


    private static class MemberInfo {
        IdentityKey id;
        IdentityKey adder; // who added this member
        ArrayList<RemoveInfo> removeMessages = new ArrayList<>(); // remove messages that removed this member
        HashSet<IdentityKey> acks; // users who have ack'd the message

        MemberInfo(IdentityKey id, IdentityKey adder) {
            this.id = id;
            this.adder = adder;
            acks = new HashSet<>();
        }

        MemberInfo(IdentityKey id, IdentityKey adder, Collection<IdentityKey> initialAcks) {
            this.id = id;
            this.adder = adder;
            acks = new HashSet<>(initialAcks);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            MemberInfo that = (MemberInfo) o;
            return id.equals(that.id) &&
                    Objects.equals(adder, that.adder) &&
                    removeMessages.equals(that.removeMessages) &&
                    acks.equals(that.acks);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, adder, removeMessages, acks);
        }
    }

    private static class RemoveInfo {
        HashSet<IdentityKey> removedUsers; // users removed by this message, including users who would have been
        // removed except they were removed previously.
        HashSet<IdentityKey> acks = new HashSet<>(); // users who have ack'd the member

        RemoveInfo(Collection<IdentityKey> removed) {
            removedUsers = new HashSet<>(removed);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            RemoveInfo that = (RemoveInfo) o;
            return removedUsers.equals(that.removedUsers) &&
                    acks.equals(that.acks);
        }

        @Override
        public int hashCode() {
            return Objects.hash(removedUsers, acks);
        }
    }
}
