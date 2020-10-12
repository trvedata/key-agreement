package org.trvedata.sgm;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.apache.thrift.TException;
import org.pcollections.HashPMap;
import org.pcollections.HashTreePMap;
import org.trvedata.sgm.crypto.*;
import org.trvedata.sgm.message.*;
import org.trvedata.sgm.misc.Constants;
import org.trvedata.sgm.misc.Logger;
import org.trvedata.sgm.misc.Utils;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;

public class FullDcgkaProtocol implements DcgkaProtocol<AckOrderer.Timestamp, MessageId, FullDcgkaProtocol.State> {

    @Override
    public ProcessReturn<State> process(State state, ControlMessage message, IdentityKey sender,
                                        AckOrderer.Timestamp causalInfo) {
        try {
            FullDcgkaMessage fullDcgkaMessage = new FullDcgkaMessage();
            Utils.deserialize(fullDcgkaMessage, message.getBytes());
            switch (fullDcgkaMessage.getType()) {
                case CREATE:
                    CreateMessage create = new CreateMessage();
                    Utils.deserialize(create, fullDcgkaMessage.getMessage());
                    return processCreate(state, create, sender, causalInfo);
                case UPDATE:
                    UpdateMessage update = new UpdateMessage();
                    Utils.deserialize(update, fullDcgkaMessage.getMessage());
                    return processUpdate(state, update, sender, causalInfo);
                case REMOVE:
                    RemoveMessage remove = new RemoveMessage();
                    Utils.deserialize(remove, fullDcgkaMessage.getMessage());
                    return processRemove(state, remove, sender, causalInfo);
                case ADD:
                    AddMessage add = new AddMessage();
                    Utils.deserialize(add, fullDcgkaMessage.getMessage());
                    return processAdd(state, add, sender, causalInfo);
                case WELCOME:
                    WelcomeMessage welcome = new WelcomeMessage();
                    Utils.deserialize(welcome, fullDcgkaMessage.getMessage());
                    return processWelcome(state, welcome, sender, causalInfo);
                case ACK:
                    AckMessage ack = new AckMessage();
                    Utils.deserialize(ack, fullDcgkaMessage.getMessage());
                    return processAck(state, ack, sender, causalInfo);
                case ACK_WITH_UPDATE:
                    AckWithUpdateMessage ackWithUpdate = new AckWithUpdateMessage();
                    Utils.deserialize(ackWithUpdate, fullDcgkaMessage.getMessage());
                    return processAckWithUpdate(state, ackWithUpdate, sender, causalInfo);
                case ADD_ACK:
                    AddAckMessage addAck = new AddAckMessage();
                    Utils.deserialize(addAck, fullDcgkaMessage.getMessage());
                    return processAddAck(state, addAck, sender, causalInfo);
                default:
                    throw new IllegalArgumentException("Unrecognized FullDcgkaMessageType: " + fullDcgkaMessage.getType());
            }
        } catch (TException | IllegalArgumentException exc) {
            throw new IllegalArgumentException("Failed to deserialize in process", exc);
        }
    }

    @Override
    public Pair<State, ControlMessage> create(State state, Collection<IdentityKey> members) {
        CreateMessage create = new CreateMessage();
        Pair<State, ? extends List<ByteBuffer>> generateResult = generateSeedSecret(state, members);
        state = generateResult.getLeft();
        create.setCiphertexts(generateResult.getRight());
        for (IdentityKey member : members) {
            create.addToIdsExcludingSender(ByteBuffer.wrap(member.serialize()));
        }

        FullDcgkaMessage message = new FullDcgkaMessage(FullDcgkaMessageType.CREATE,
                ByteBuffer.wrap(Utils.serialize(create)));
        return Pair.of(state, ControlMessage.of(Utils.serialize(message)));
    }

    private ProcessReturn<State> processCreate(State state, CreateMessage create, IdentityKey sender,
                                               AckOrderer.Timestamp causalInfo) {
        ArrayList<IdentityKey> members = deserializeIdList(create.getIdsExcludingSender());
        members.add(sender);
        if (!members.contains(state.id)) {
            // Throw an exception, to fulfill the condition stated in the Javadoc for DcgkaProtocol.process.
            throw new IllegalArgumentException("Welcome is not for us: " + causalInfo.messageId);
        }
        state = state.setStrongRemoveDGM(new StrongRemoveDgm(members, state.id));
        Triple<State, AckMessage, ForwardSecureEncryptionProtocol.Key> processSeedSecretReturn =
                processSeedSecret(state, sender, causalInfo.messageId, create.getCiphertexts());
        state = processSeedSecretReturn.getLeft();
        state = state.setCreateMessageId(causalInfo.messageId);
        ControlMessage response;
        if (processSeedSecretReturn.getMiddle() == null) response = ControlMessage.of(null);
        else {
            FullDcgkaMessage ackWrapped = new FullDcgkaMessage(FullDcgkaMessageType.ACK,
                    ByteBuffer.wrap(Utils.serialize(processSeedSecretReturn.getMiddle())));
            response = ControlMessage.of(Utils.serialize(ackWrapped));
        }
        return new ProcessReturn<>(state, DcgkaMessageType.WELCOME, response,
                processSeedSecretReturn.getRight(), null, members, Collections.emptyList(),
                causalInfo.messageId, Collections.emptyList());
    }

    private ProcessReturn<State> processAck(State state, AckMessage ack, IdentityKey sender,
                                            AckOrderer.Timestamp causalInfo) {
        if (causalInfo.ackedMessageId == null) {
            throw new IllegalArgumentException("ackedMessageId is null for ack message");
        }
        // Note acking the message will fail if it's an ack of the user's own removal.
        // Thus we will refuse to process messages from a user that depend on their own removal.
        Collection<MessageId> ackedMessageIds;
        if (!sender.equals(state.id)) {
            if (state.strongRemoveDGM.isAdd(causalInfo.ackedMessageId) ||
                    state.strongRemoveDGM.isRemove(causalInfo.ackedMessageId)) {
                // This condition will fail for acks of the creation and of updates
                state.strongRemoveDGM.ack(sender, causalInfo.ackedMessageId);
            }
            ackedMessageIds = Collections.singletonList(causalInfo.ackedMessageId);
        } else ackedMessageIds = Collections.emptyList();

        ForwardSecureEncryptionProtocol.Key updateSecret;
        PuncturablePseudorandomFunction pprf = state.pprfs.get(causalInfo.ackedMessageId);
        if (pprf == null) {
            throw new IllegalArgumentException("No PPRF for acked message");
        }
        Pair<PuncturablePseudorandomFunction, byte[]> chainUpdatePair = pprf.popValue(sender.serialize());
        if (chainUpdatePair.getRight() != null) {
            // Derive the sender's perMemberSecret from pprf.
            state = state.putPprf(causalInfo.messageId, chainUpdatePair.getLeft());
            Pair<State, ForwardSecureEncryptionProtocol.Key> keyUpdatePair =
                    prng(state, sender, chainUpdatePair.getRight());
            state = keyUpdatePair.getLeft();
            updateSecret = keyUpdatePair.getRight();
        } else {
            // See if we got forwarded the perMemberSecret.
            ByteBuffer myForward = ack.getForwards().get(ByteBuffer.wrap(state.id.serialize()));
            if (myForward == null) {
                updateSecret = ForwardSecureEncryptionProtocol.Key.of(null);
                Logger.i("FullDcgkaProtocol", "No derived secret for member " + sender.hashCode() +
                        " when acking message " + causalInfo.ackedMessageId + ".  This should only " +
                        "happen if the sender was added concurrently to that message and the ack.");
            } else {
                // We did get forwarded the perMemberSecret.
                Pair<State, byte[]> decryptionResult = decryptFrom(state, sender,
                        Utils.asArray(myForward));
                state = decryptionResult.getLeft();
                Pair<State, ForwardSecureEncryptionProtocol.Key> keyUpdatePair =
                        prng(state, sender, decryptionResult.getRight());
                state = keyUpdatePair.getLeft();
                updateSecret = keyUpdatePair.getRight();
            }
        }

        return new ProcessReturn<>(state, DcgkaMessageType.OTHER, ControlMessage.of(null),
                updateSecret, null, Collections.emptyList(),
                Collections.emptyList(), causalInfo.messageId, ackedMessageIds);
    }

    @Override
    public Pair<State, ControlMessage> update(State state) {
        Pair<State, UpdateMessage> internal = updateInternal(state);
        FullDcgkaMessage message = new FullDcgkaMessage(FullDcgkaMessageType.UPDATE,
                ByteBuffer.wrap(Utils.serialize(internal.getRight())));
        return Pair.of(internal.getLeft(), ControlMessage.of(Utils.serialize(message)));
    }

    private Pair<State, UpdateMessage> updateInternal(State state) {
        UpdateMessage update = new UpdateMessage();
        Pair<State, ? extends List<ByteBuffer>> generateResult = generateSeedSecret(state,
                state.strongRemoveDGM.queryWholeWithoutMe());
        state = generateResult.getLeft();
        update.setCiphertexts(generateResult.getRight());
        return Pair.of(state, update);
    }

    private ProcessReturn<State> processUpdate(State state, UpdateMessage update, IdentityKey sender,
                                               AckOrderer.Timestamp causalInfo) {
        Triple<State, AckMessage, ForwardSecureEncryptionProtocol.Key> processSeedSecretReturn =
                processSeedSecret(state, sender, causalInfo.messageId, update.getCiphertexts());
        state = processSeedSecretReturn.getLeft();
        ControlMessage response;
        if (processSeedSecretReturn.getMiddle() == null) response = ControlMessage.of(null);
        else {
            FullDcgkaMessage ackWrapped = new FullDcgkaMessage(FullDcgkaMessageType.ACK,
                    ByteBuffer.wrap(Utils.serialize(processSeedSecretReturn.getMiddle())));
            response = ControlMessage.of(Utils.serialize(ackWrapped));
        }
        return new ProcessReturn<>(state, DcgkaMessageType.UPDATE, response,
                processSeedSecretReturn.getRight(), null, Collections.emptyList(), Collections.emptyList(),
                causalInfo.messageId, Collections.emptyList());
    }

    @Override
    public Pair<State, ControlMessage> remove(State state, IdentityKey removed) {
        RemoveMessage remove = new RemoveMessage();
        HashSet<IdentityKey> recipients = state.strongRemoveDGM.queryWholeWithoutMe();
        recipients.remove(removed);
        Pair<State, ? extends List<ByteBuffer>> generateResult = generateSeedSecret(state,
                recipients);
        state = generateResult.getLeft();
        remove.setCiphertexts(generateResult.getRight());
        remove.setRemoved(removed.serialize());

        FullDcgkaMessage message = new FullDcgkaMessage(FullDcgkaMessageType.REMOVE,
                ByteBuffer.wrap(Utils.serialize(remove)));
        return Pair.of(state, ControlMessage.of(Utils.serialize(message)));
    }

    private ProcessReturn<State> processRemove(State state, RemoveMessage remove, IdentityKey sender,
                                               AckOrderer.Timestamp causalInfo) {
        IdentityKey removed = new IdentityKey(remove.getRemoved());
        Collection<IdentityKey> removedCollection = state.strongRemoveDGM.remove(sender,
                Collections.singleton(removed), causalInfo.messageId);
        if (removedCollection.contains(state.id)) {
            // TODO: need to revert the MembershipSet.  Will be fixed once it's persistent.
            // Return the result without processing the seed secret, since we can't.
            return new ProcessReturn<>(state, DcgkaMessageType.REMOVE, ControlMessage.of(null),
                    ForwardSecureEncryptionProtocol.Key.of(null), removed, Collections.emptyList(), removedCollection,
                    causalInfo.messageId, Collections.emptyList());
        }

        Triple<State, AckMessage, ForwardSecureEncryptionProtocol.Key> processSeedSecretReturn =
                processSeedSecret(state, sender, causalInfo.messageId, remove.getCiphertexts());
        state = processSeedSecretReturn.getLeft();

        // Do ack-with-update if needed
        ControlMessage response;
        HashSet<IdentityKey> diffSet = state.strongRemoveDGM.queryView(sender);
        diffSet.removeAll(state.strongRemoveDGM.queryWhole());
        if (!diffSet.isEmpty()) {
            Pair<State, UpdateMessage> updateResult = updateInternal(state);
            state = updateResult.getLeft();
            AckWithUpdateMessage ackWithUpdate = new AckWithUpdateMessage(processSeedSecretReturn.getMiddle(),
                    updateResult.getRight());
            FullDcgkaMessage ackWithUpdateWrapped = new FullDcgkaMessage(FullDcgkaMessageType.ACK_WITH_UPDATE,
                    ByteBuffer.wrap(Utils.serialize(ackWithUpdate)));
            response = ControlMessage.of(Utils.serialize(ackWithUpdateWrapped));
        } else {
            if (processSeedSecretReturn.getMiddle() == null) response = ControlMessage.of(null);
            else {
                FullDcgkaMessage ackWrapped = new FullDcgkaMessage(FullDcgkaMessageType.ACK,
                        ByteBuffer.wrap(Utils.serialize(processSeedSecretReturn.getMiddle())));
                response = ControlMessage.of(Utils.serialize(ackWrapped));
            }
        }

        return new ProcessReturn<>(state, DcgkaMessageType.REMOVE, response,
                processSeedSecretReturn.getRight(), removed, Collections.emptyList(), removedCollection,
                causalInfo.messageId, Collections.emptyList());
    }

    private ProcessReturn<State> processAckWithUpdate(State state, AckWithUpdateMessage ackWithUpdate,
                                                      IdentityKey sender, AckOrderer.Timestamp causalInfo) {
        ProcessReturn<State> ackResult = processAck(state, ackWithUpdate.getAck(), sender, causalInfo);
        ProcessReturn<State> updateResult = processUpdate(ackResult.state, ackWithUpdate.getUpdate(),
                sender, causalInfo);
        return new ProcessReturn<>(updateResult.state, DcgkaMessageType.UPDATE, updateResult.responseMessage,
                updateResult.updateSecret, null, Collections.emptyList(), Collections.emptyList(),
                causalInfo.messageId, ackResult.ackedMessageIds);
    }

    @Override
    public Triple<State, ControlMessage, ControlMessage> add(State state, IdentityKey added) {
        // TODO: new user should add themselves after deserializing
        // TODO: once MembershipSet is immutable, instead of doing that, serialize the MembershipSet
        // with the new user added?  Change in process as well.
        Pair<State, byte[]> myPrfForAdded = encryptTo(state, added, state.prfPrngs.get(state.id));
        state = myPrfForAdded.getLeft();
        WelcomeMessage welcome = new WelcomeMessage(ByteBuffer.wrap(state.strongRemoveDGM.serialize().getLeft()),
                ByteBuffer.wrap(myPrfForAdded.getRight()));
        FullDcgkaMessage welcomeWrapped = new FullDcgkaMessage(FullDcgkaMessageType.WELCOME,
                ByteBuffer.wrap(Utils.serialize(welcome)));
        AddMessage add = new AddMessage(ByteBuffer.wrap(added.serialize()));
        FullDcgkaMessage addWrapped = new FullDcgkaMessage(FullDcgkaMessageType.ADD,
                ByteBuffer.wrap(Utils.serialize(add)));
        return Triple.of(state, ControlMessage.of(Utils.serialize(welcomeWrapped)),
                ControlMessage.of(Utils.serialize(addWrapped)));
    }

    private ProcessReturn<State> processAdd(State state, AddMessage add,
                                            IdentityKey sender, AckOrderer.Timestamp causalInfo) {
        IdentityKey added = new IdentityKey(add.getAdded());
        Collection<IdentityKey> addedCollection;
        if (!state.strongRemoveDGM.add(sender, added, causalInfo.messageId)) {
            addedCollection = Collections.singletonList(added);
        } else addedCollection = Collections.emptyList();

        ForwardSecureEncryptionProtocol.Key updateSecret;
        if (state.strongRemoveDGM.queryView(sender).contains(state.id)) {
            Pair<State, ForwardSecureEncryptionProtocol.Key> prngWelcome = prng(state,
                    sender, "welcome".getBytes());
            state = prngWelcome.getLeft();
            PuncturablePseudorandomFunction pprf = new PuncturablePseudorandomFunction(prngWelcome.getRight().getBytes(),
                    Collections.singletonList(add.getAdded()));
            state = state.putPprf(causalInfo.messageId, pprf);
            Pair<State, ForwardSecureEncryptionProtocol.Key> prngAdd = prng(state,
                    sender, "add".getBytes());
            state = prngAdd.getLeft();
            updateSecret = prngAdd.getRight();
        } else updateSecret = ForwardSecureEncryptionProtocol.Key.of(null);

        ControlMessage response;
        if (sender.equals(state.id)) response = ControlMessage.of(null);
        else {
            Pair<State, byte[]> myPrfForAdded = encryptTo(state, added, state.prfPrngs.get(state.id));
            state = myPrfForAdded.getLeft();
            AddAckMessage addAck = new AddAckMessage(ByteBuffer.wrap(myPrfForAdded.getRight()));
            FullDcgkaMessage addAckWrapped = new FullDcgkaMessage(FullDcgkaMessageType.ADD_ACK,
                    ByteBuffer.wrap(Utils.serialize(addAck)));
            response = ControlMessage.of(Utils.serialize(addAckWrapped));
            state = state.setLastAcked(causalInfo.messageId);
        }

        return new ProcessReturn<>(state, DcgkaMessageType.ADD, response,
                updateSecret, added, addedCollection, Collections.emptyList(),
                causalInfo.messageId, Collections.emptyList());
    }

    private ProcessReturn<State> processAddAck(State state, AddAckMessage ack, IdentityKey sender,
                                               AckOrderer.Timestamp causalInfo) {
        if (causalInfo.ackedMessageId == null) {
            throw new IllegalArgumentException("ackedMessageId is null for add-ack message");
        }

        Collection<MessageId> ackedMessageIds;
        if (!sender.equals(state.id)) {
            state.strongRemoveDGM.ack(sender, causalInfo.ackedMessageId);
            ackedMessageIds = Collections.singletonList(causalInfo.ackedMessageId);
        } else ackedMessageIds = Collections.emptyList();

        if (causalInfo.ackedMessageId.equals(state.addMessageId)) {
            // The acked message added us
            Pair<State, byte[]> decryptionResult = decryptFrom(state, sender, ack.getPrfForAdded());
            state = decryptionResult.getLeft();
            state = state.putChainKey(sender, decryptionResult.getRight());
        }

        ForwardSecureEncryptionProtocol.Key updateSecret;
        if (state.strongRemoveDGM.queryView(sender).contains(state.id)) {
            Pair<State, ForwardSecureEncryptionProtocol.Key> prngAdd = prng(state,
                    sender, "add".getBytes());
            state = prngAdd.getLeft();
            updateSecret = prngAdd.getRight();
        } else updateSecret = ForwardSecureEncryptionProtocol.Key.of(null);

        return new ProcessReturn<>(state, DcgkaMessageType.OTHER, ControlMessage.of(null),
                updateSecret, null, Collections.emptyList(),
                Collections.emptyList(), causalInfo.messageId, ackedMessageIds);
    }

    private ProcessReturn<State> processWelcome(State state, WelcomeMessage welcome, IdentityKey sender,
                                                AckOrderer.Timestamp causalInfo) {
        StrongRemoveDgm strongRemoveDGM = StrongRemoveDgm.deserialize(welcome.getStrongRemoveDgm(), state.id)
                .getLeft();
        strongRemoveDGM.add(sender, state.id, causalInfo.messageId);
        state = state.setStrongRemoveDGM(strongRemoveDGM);
        state = state.setAddMessageId(causalInfo.messageId);
        // If the Welcome is not for us, two-party decryption will fail, so decrypt will throw an
        // IllegalArgumentException.  Thus we fulfill the condition stated in the Javadoc for
        // DcgkaProtocol.process.
        Pair<State, byte[]> decryptReturn = decryptFrom(state, sender, welcome.getPrfForAdded());
        state = decryptReturn.getLeft();
        state = state.putChainKey(sender, decryptReturn.getRight());

        Pair<State, ForwardSecureEncryptionProtocol.Key> prngWelcome = prng(state,
                sender, "welcome".getBytes());
        state = prngWelcome.getLeft();
        PuncturablePseudorandomFunction pprf = new PuncturablePseudorandomFunction(prngWelcome.getRight().getBytes(),
                Collections.singletonList(state.id.serialize()));
        state = state.putPprf(causalInfo.messageId, pprf);
        Pair<State, ForwardSecureEncryptionProtocol.Key> prngAdd = prng(state,
                sender, "add".getBytes());
        state = prngAdd.getLeft();
        ForwardSecureEncryptionProtocol.Key updateSecret = prngAdd.getRight();

        AckMessage ack = new AckMessage(Collections.emptyMap());
        FullDcgkaMessage ackWrapped = new FullDcgkaMessage(FullDcgkaMessageType.ACK,
                ByteBuffer.wrap(Utils.serialize(ack)));
        state = state.setLastAcked(causalInfo.messageId);

        return new ProcessReturn<>(state, DcgkaMessageType.WELCOME, ControlMessage.of(Utils.serialize(ackWrapped)),
                updateSecret, null, state.strongRemoveDGM.queryWhole(), Collections.emptyList(),
                causalInfo.messageId, Collections.emptySet());
    }

    /**
     * Generates a random secret, encrypts it for recipients in sorted order (skipping over state.id),
     * adds those encryptions to message (mutably), and stores the secret in an updated state,
     * which is returned.
     */
    private Pair<State, ? extends List<ByteBuffer>> generateSeedSecret(State state, Collection<IdentityKey> recipients) {
        ArrayList<ByteBuffer> result = new ArrayList<>();
        byte[] secret = Utils.getSecureRandomBytes(Constants.KEY_SIZE_BYTES);
        List<IdentityKey> sortedRecipients =
                recipients.stream().sorted().collect(Collectors.toList());
        for (IdentityKey recipient : sortedRecipients) {
            if (!recipient.equals(state.id)) {// skip me
                Pair<State, byte[]> encryptReturn = encryptTo(state, recipient, secret);
                state = encryptReturn.getLeft();
                result.add(ByteBuffer.wrap(encryptReturn.getRight()));
            }
        }
        return Pair.of(state.setNextSeed(secret), result);
    }

    private Pair<State, byte[]> encryptTo(State state, IdentityKey recipient, byte[] plaintext) {
        TwoPartyProtocol twoPartyProtocol = state.twoPartyProtocols.get(recipient);
        if (twoPartyProtocol == null) {
            twoPartyProtocol = new TwoPartyProtocol(state.preKeySecret, state.preKeySource, recipient);
        }
        Pair<TwoPartyProtocol, byte[]> encrypted = twoPartyProtocol.encrypt(plaintext);
        state = state.putTwoPartyProtocol(recipient, encrypted.getLeft());
        return Pair.of(state, encrypted.getRight());
    }

    /**
     * Here sendersView should be the same view of the group members that sender passed
     * to addSecret as recipients.  If sender is us, this will instead use sender.nextMessageSecret.
     */
    private Triple<State, AckMessage, ForwardSecureEncryptionProtocol.Key> processSeedSecret(
            State state, IdentityKey sender, MessageId messageId, List<ByteBuffer> ciphertexts) {
        HashSet<IdentityKey> recipients = state.strongRemoveDGM.queryView(sender);
        recipients.remove(sender);

        byte[] seed;
        if (sender.equals(state.id)) {
            seed = state.nextSeed;
            state = state.setNextSeed(null);
        } else if (recipients.contains(state.id)) {
            // Count how many members are before me; that's my index
            int myIndex = 0;
            for (IdentityKey member : recipients) {
                if (!member.equals(sender) && member.compareTo(state.id) < 0) myIndex++;
            }
            Pair<State, byte[]> decryptResult = decryptFrom(state, sender, Utils.asArray(ciphertexts.get(myIndex)));
            state = decryptResult.getLeft();
            seed = decryptResult.getRight();
        } else seed = null;

        ForwardSecureEncryptionProtocol.Key updateSecret;
        if (seed == null) updateSecret = ForwardSecureEncryptionProtocol.Key.of(null);
        else {
            PuncturablePseudorandomFunction pprf = new PuncturablePseudorandomFunction(seed,
                    state.strongRemoveDGM.queryView(sender).stream().map(IdentityKey::serialize).collect(Collectors.toList()));
            Pair<PuncturablePseudorandomFunction, byte[]> chainUpdatePair = pprf.popValue(sender.serialize());
            state = state.putPprf(messageId, chainUpdatePair.getLeft());
            Pair<State, ForwardSecureEncryptionProtocol.Key> prngResult = prng(state, sender, chainUpdatePair.getRight());
            state = prngResult.getLeft();
            updateSecret = prngResult.getRight();
        }

        AckMessage ack;
        if (sender.equals(state.id)) ack = null;
        else {
            Map<ByteBuffer, ByteBuffer> forwards;
            if (recipients.contains(state.id)) {
                // Forward my per-member secret to concurrently added users
                forwards = new HashMap<>();
                HashSet<IdentityKey> needsForwarding = state.strongRemoveDGM.queryWhole();
                needsForwarding.removeAll(recipients);
                needsForwarding.remove(sender);
                for (IdentityKey toForward : needsForwarding) {
                    // Note the pop doesn't do anything because we ignore the returned pprf
                    Pair<State, byte[]> encryptionResult = encryptTo(state, toForward,
                            state.pprfs.get(messageId).popValue(state.id.serialize()).getRight());
                    state = encryptionResult.getLeft();
                    forwards.put(ByteBuffer.wrap(toForward.serialize()),
                            ByteBuffer.wrap(encryptionResult.getRight()));
                }
            } else forwards = Collections.emptyMap();
            ack = new AckMessage(forwards);
            state = state.setLastAcked(messageId);
        }

        return Triple.of(state, ack, updateSecret);
    }

    private Pair<State, byte[]> decryptFrom(State state, IdentityKey sender, byte[] ciphertext) {
        TwoPartyProtocol twoPartyProtocol = state.twoPartyProtocols.get(sender);
        if (twoPartyProtocol == null) {
            twoPartyProtocol = new TwoPartyProtocol(state.preKeySecret, state.preKeySource, sender);
        }
        Pair<TwoPartyProtocol, byte[]> decrypted = twoPartyProtocol.decrypt(ciphertext);
        if (decrypted == null) {
            throw new IllegalArgumentException("Failed to decrypt TwoPartyProtocol message from " + sender.hashCode());
        }
        state = state.putTwoPartyProtocol(sender, decrypted.getLeft());
        return Pair.of(state, decrypted.getRight());
    }

    private Pair<State, ForwardSecureEncryptionProtocol.Key> prng(State state, IdentityKey sender, byte[] chainUpdate) {
        // Combine chainUpdate.getRight() with current chain key to get keyUpdate and new chain key
        byte[] chainKey = state.prfPrngs.get(sender);
        byte[] keyUpdate;
        if (chainKey == null) {
            keyUpdate = Utils.hash("update", chainUpdate);
            chainKey = Utils.hash("chain", chainUpdate);
        } else {
            keyUpdate = Utils.hash("update", chainKey, chainUpdate);
            chainKey = Utils.hash("chain", chainKey, chainUpdate);
        }
        return Pair.of(state.putChainKey(sender, chainKey), ForwardSecureEncryptionProtocol.Key.of(keyUpdate));
    }

    private ArrayList<IdentityKey> deserializeIdList(List<ByteBuffer> ids) {
        ArrayList<IdentityKey> result = new ArrayList<>();
        for (ByteBuffer id : ids) {
            result.add(new IdentityKey(Utils.asArray(id)));
        }
        return result;
    }

    public Pair<State, MessageId> getOrdererInput(State state) {
        State newState = state;
        if (state.lastAcked != null) {
            // Set lackAcked to null so we only send each ack once.
            newState = state.setLastAcked(null);
        }
        return Pair.of(newState, state.lastAcked);
    }

    @Override
    public Collection<IdentityKey> getMembers(State state) {
        return state.strongRemoveDGM.queryWhole();
    }

    @Override
    public Collection<IdentityKey> getMembersAndRemovedMembers(State state) {
        return state.strongRemoveDGM.getMembersAndRemovedMembers();
    }

    public static class State implements DcgkaProtocol.State {
        private final IdentityKey id;
        private final PreKeySecret preKeySecret;
        private final PreKeySource preKeySource;
        private final HashPMap<IdentityKey, TwoPartyProtocol> twoPartyProtocols;
        private final StrongRemoveDgm strongRemoveDGM; // TODO: make immutable
        private final HashPMap<MessageId, PuncturablePseudorandomFunction> pprfs;
        private final HashPMap<IdentityKey, byte[]> prfPrngs;
        private final MessageId addMessageId; // MessageId of our add message.  Null if we were added at group creation.
        private final MessageId createMessageId; // MessageId of the group creation message.  Null if we weren't an
        // initial member.
        private final MessageId lastAcked; // last message that was acked
        private final byte[] nextSeed; // the secret in a message we just generated
        // which should be processed next

        public State(IdentityKey id, PreKeySecret preKeySecret, PreKeySource preKeySource) {
            // membershipSet is initialized on welcome
            this.id = id;
            this.preKeySecret = preKeySecret;
            this.preKeySource = preKeySource;
            this.twoPartyProtocols = HashTreePMap.empty();
            this.strongRemoveDGM = StrongRemoveDgm.empty(id);
            this.pprfs = HashTreePMap.empty();
            this.prfPrngs = HashTreePMap.empty();
            this.addMessageId = null;
            this.createMessageId = null;
            this.lastAcked = null;
            this.nextSeed = null;
        }

        private State(State old,
                      HashPMap<IdentityKey, TwoPartyProtocol> twoPartyProtocols, StrongRemoveDgm strongRemoveDGM,
                      HashPMap<MessageId, PuncturablePseudorandomFunction> pprfs, HashPMap<IdentityKey, byte[]> prfPrngs,
                      MessageId addMessageId, MessageId createMessageId, MessageId lastAcked, byte[] nextSeed) {
            this.id = old.id;
            this.preKeySecret = old.preKeySecret;
            this.preKeySource = old.preKeySource;
            this.twoPartyProtocols = twoPartyProtocols;
            this.strongRemoveDGM = strongRemoveDGM;
            this.pprfs = pprfs;
            this.prfPrngs = prfPrngs;
            this.addMessageId = addMessageId;
            this.createMessageId = createMessageId;
            this.lastAcked = lastAcked;
            this.nextSeed = nextSeed;
        }

        private State setStrongRemoveDGM(StrongRemoveDgm newStrongRemoveDgm) {
            return new State(this, this.twoPartyProtocols, newStrongRemoveDgm,
                    this.pprfs, this.prfPrngs, this.addMessageId, this.createMessageId, this.lastAcked, this.nextSeed);
        }

        private State setNextSeed(byte[] newNextMessageSecret) {
            return new State(this, this.twoPartyProtocols, this.strongRemoveDGM,
                    this.pprfs, this.prfPrngs, this.addMessageId, this.createMessageId, this.lastAcked, newNextMessageSecret);
        }

        private State setLastAcked(MessageId newLastAcked) {
            return new State(this, this.twoPartyProtocols, this.strongRemoveDGM,
                    this.pprfs, this.prfPrngs, this.addMessageId, this.createMessageId, newLastAcked, this.nextSeed);
        }

        private State setAddMessageId(MessageId newAddMessageId) {
            return new State(this, this.twoPartyProtocols, this.strongRemoveDGM,
                    this.pprfs, this.prfPrngs, newAddMessageId, this.createMessageId, this.lastAcked, this.nextSeed);
        }

        private State setCreateMessageId(MessageId newCreateMessageId) {
            return new State(this, this.twoPartyProtocols, this.strongRemoveDGM,
                    this.pprfs, this.prfPrngs, this.addMessageId, newCreateMessageId, this.lastAcked, this.nextSeed);
        }

        private State putPprf(MessageId messageId, PuncturablePseudorandomFunction newPprf) {
            return new State(this, this.twoPartyProtocols, this.strongRemoveDGM,
                    this.pprfs.plus(messageId, newPprf), this.prfPrngs, this.addMessageId, this.createMessageId,
                    this.lastAcked, this.nextSeed);
        }

        private State putChainKey(IdentityKey member, byte[] newChainKey) {
            return new State(this, this.twoPartyProtocols, this.strongRemoveDGM,
                    this.pprfs, this.prfPrngs.plus(member, newChainKey), this.addMessageId, this.createMessageId,
                    this.lastAcked, this.nextSeed);
        }

        private State putTwoPartyProtocol(IdentityKey member, TwoPartyProtocol twoPartyProtocol) {
            return new State(this, this.twoPartyProtocols.plus(member, twoPartyProtocol),
                    this.strongRemoveDGM, this.pprfs, this.prfPrngs, this.addMessageId, this.createMessageId,
                    this.lastAcked, this.nextSeed);
        }
    }
}
