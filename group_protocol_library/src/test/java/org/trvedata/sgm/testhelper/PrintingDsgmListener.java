package org.trvedata.sgm.testhelper;

import org.trvedata.sgm.DsgmClient;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.message.MessageId;
import org.trvedata.sgm.misc.Logger;

import java.util.ArrayList;
import java.util.HashMap;

/**
 * A {@link DsgmClient.DsgmListener} that prints all events to {@link Logger}.
 */
public class PrintingDsgmListener implements DsgmClient.DsgmListener {
    private final String myName;
    private final HashMap<IdentityKey, String> names;

    public PrintingDsgmListener(String myName, HashMap<IdentityKey, String> names) {
        this.myName = myName;
        this.names = names;
    }

    @Override
    public void onIncomingMessage(IdentityKey sender, byte[] plaintext) {
        Logger.i("PrintingDczkaListener", myName + ": Incoming message from " + names.get(sender) +
                ", plaintext: " + new String(plaintext));
    }

    @Override
    public void onUpdate(IdentityKey updater, Object messageId) {
        String messageIdString = (messageId instanceof MessageId) ? (", number: " + ((MessageId) messageId).number) : "";
        Logger.i("PrintingDczkaListener", myName + ": Update from " + names.get(updater) + messageIdString);
    }

    @Override
    public void onAdd(IdentityKey adder, IdentityKey added, Object messageId) {
        String messageIdString = (messageId instanceof MessageId) ? (", number: " + ((MessageId) messageId).number) : "";
        Logger.i("PrintingDczkaListener", myName + ": Add from " + names.get(adder) +
                ", added: " + names.get(added) + messageIdString);
    }

    @Override
    public void onRemove(IdentityKey remover, ArrayList<IdentityKey> removed, Object messageId) {
        String messageIdString = (messageId instanceof MessageId) ? (", number: " + ((MessageId) messageId).number) : "";
        String removedString = "[";
        for (IdentityKey oneRemoved : removed) removedString += names.get(oneRemoved) + ", ";
        removedString += "]";
        Logger.i("PrintingDczkaListener", myName + ": Remove from " + names.get(remover) +
                ", removed: " + removedString + messageIdString);
    }

    @Override
    public void onAck(IdentityKey acker, Object acked) {
        String messageIdString = "";
        if (acked instanceof MessageId) {
            MessageId ackedId = (MessageId) acked;
            messageIdString = ", acked message: (" + names.get(ackedId.author) + ", " + ackedId.number + ")";
        }
        Logger.i("PrintingDczkaListener", myName + ": Ack from " + names.get(acker) + messageIdString);
    }
}
