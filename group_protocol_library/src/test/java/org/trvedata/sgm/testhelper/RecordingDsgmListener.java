package org.trvedata.sgm.testhelper;

import org.trvedata.sgm.DsgmClient;
import org.trvedata.sgm.crypto.IdentityKey;

import java.util.ArrayList;

/**
 * A {@link DsgmClient.DsgmListener} that records all events by appending them to separate lists.
 */
public class RecordingDsgmListener implements DsgmClient.DsgmListener {

    public final ArrayList<RecordedIncomingMessage> recordedIncomingMessages = new ArrayList<>();
    public final ArrayList<RecordedUpdate> recordedUpdates = new ArrayList<>();
    public final ArrayList<RecordedAdd> recordedAdds = new ArrayList<>();
    public final ArrayList<RecordedRemove> recordedRemoves = new ArrayList<>();
    public final ArrayList<RecordedAck> recordedAcks = new ArrayList<>();

    public RecordingDsgmListener() {
        // nop
    }

    @Override
    public void onIncomingMessage(IdentityKey sender, byte[] plaintext) {
        recordedIncomingMessages.add(new RecordedIncomingMessage(sender, plaintext));
    }

    public static class RecordedIncomingMessage {
        public final IdentityKey sender;
        public final byte[] plaintext;

        public RecordedIncomingMessage(IdentityKey sender, byte[] plaintext) {
            this.sender = sender;
            this.plaintext = plaintext;
        }
    }

    @Override
    public void onUpdate(IdentityKey updater, Object messageId) {
        recordedUpdates.add(new RecordedUpdate(updater, messageId));
    }

    @Override
    public void onAdd(IdentityKey adder, IdentityKey added, Object messageId) {
        recordedAdds.add(new RecordedAdd(adder, added, messageId));
    }

    public static class RecordedUpdate {
        public final IdentityKey updater;
        public final Object messageId;

        public RecordedUpdate(IdentityKey updater, Object messageId) {
            this.updater = updater;
            this.messageId = messageId;
        }
    }

    public static class RecordedAdd {
        public final IdentityKey adder;
        public final IdentityKey added;
        public final Object messageId;

        public RecordedAdd(IdentityKey adder, IdentityKey added, Object messageId) {
            this.adder = adder;
            this.added = added;
            this.messageId = messageId;
        }
    }

    @Override
    public void onRemove(IdentityKey remover, ArrayList<IdentityKey> removed, Object messageId) {
        recordedRemoves.add(new RecordedRemove(remover, removed, messageId));
    }

    public static class RecordedRemove {
        public final IdentityKey remover;
        public final ArrayList<IdentityKey> removed;
        public final Object messageId;

        public RecordedRemove(IdentityKey remover, ArrayList<IdentityKey> removed, Object messageId) {
            this.remover = remover;
            this.removed = removed;
            this.messageId = messageId;
        }
    }

    @Override
    public void onAck(IdentityKey acker, Object acked) {
        recordedAcks.add(new RecordedAck(acker, acked));
    }

    public static class RecordedAck {
        public final IdentityKey acker;
        public final Object acked;

        public RecordedAck(IdentityKey acker, Object acked) {
            this.acker = acker;
            this.acked = acked;
        }
    }
}
