package org.trvedata.sgm;

import org.apache.commons.lang3.tuple.Pair;
import org.trvedata.sgm.crypto.IdentityKeyPair;
import org.trvedata.sgm.crypto.PreKeySecret;
import org.trvedata.sgm.crypto.PreKeySource;
import org.trvedata.sgm.message.MessageId;
import org.trvedata.sgm.message.ModularMessage;
import org.trvedata.sgm.message.SignedMessage;

public class FullDsgmProtocol extends ModularDsgm<AckOrderer.Timestamp, MessageId, FullDcgkaProtocol.State,
        InOrderForwardSecureEncryptionProtocol.State, AckOrderer.State<Pair<ModularMessage, SignedMessage>>,
        RotatingSignatureProtocol.State> {
    public FullDsgmProtocol() {
        super(new FullDcgkaProtocol(),
                new InOrderForwardSecureEncryptionProtocol(),
                new AckOrderer<>(), new RotatingSignatureProtocol());
    }

    public static class State extends ModularDsgm.State<FullDcgkaProtocol.State,
            InOrderForwardSecureEncryptionProtocol.State, AckOrderer.State<Pair<ModularMessage, SignedMessage>>,
            RotatingSignatureProtocol.State> {
        public State(IdentityKeyPair idPair, PreKeySecret preKeySecret, PreKeySource preKeySource) {
            super(idPair.getPublicKey(), new FullDcgkaProtocol.State(idPair.getPublicKey(), preKeySecret, preKeySource),
                    new AckOrderer.State<>(idPair.getPublicKey()), new RotatingSignatureProtocol.State(idPair));
        }
    }
}
