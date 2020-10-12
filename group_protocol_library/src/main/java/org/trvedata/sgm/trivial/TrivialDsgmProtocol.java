package org.trvedata.sgm.trivial;

import org.apache.commons.lang3.tuple.Pair;
import org.trvedata.sgm.AckOrderer;
import org.trvedata.sgm.ModularDsgm;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.message.MessageId;
import org.trvedata.sgm.message.ModularMessage;
import org.trvedata.sgm.message.SignedMessage;

public class TrivialDsgmProtocol extends ModularDsgm<AckOrderer.Timestamp, MessageId, TrivialDcgkaProtocol.State,
        TrivialForwardSecureEncryptionProtocol.State, TrivialOrderer.State<Pair<ModularMessage, SignedMessage>>,
        TrivialSignatureProtocol.State> {
    public TrivialDsgmProtocol() {
        super(new TrivialDcgkaProtocol(),
                new TrivialForwardSecureEncryptionProtocol(),
                new TrivialOrderer<>(), new TrivialSignatureProtocol());
    }

    public static class State extends ModularDsgm.State<TrivialDcgkaProtocol.State,
            TrivialForwardSecureEncryptionProtocol.State, TrivialOrderer.State<Pair<ModularMessage, SignedMessage>>,
            TrivialSignatureProtocol.State> {
        public State(IdentityKey id) {
            super(id, new TrivialDcgkaProtocol.State(id),
                    new TrivialOrderer.State<>(), new TrivialSignatureProtocol.State());
        }
    }
}
