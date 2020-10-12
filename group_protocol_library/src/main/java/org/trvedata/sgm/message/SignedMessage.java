package org.trvedata.sgm.message;

import org.apache.thrift.TException;
import org.trvedata.sgm.SignatureProtocol;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.misc.Utils;

import java.nio.ByteBuffer;

public class SignedMessage {
    public final ModularMessage.Serialized content;
    public final IdentityKey sender;
    public final SignatureProtocol.Signature signature;

    public SignedMessage(ModularMessage.Serialized content, IdentityKey sender, SignatureProtocol.Signature signature) {
        this.content = content;
        this.sender = sender;
        this.signature = signature;
    }

    public SignedMessage(byte[] serialized) {
        try {
            SignedMessageStruct struct = new SignedMessageStruct();
            Utils.deserialize(struct, serialized);
            this.content = ModularMessage.Serialized.of(struct.getContent());
            this.sender = new IdentityKey(struct.getSender());
            this.signature = SignatureProtocol.Signature.of(struct.getSignature());
        } catch (TException | IllegalArgumentException exc) {
            throw new IllegalArgumentException("Failed to deserialize ModularMessageStruct", exc);
        }
    }

    public byte[] serialize() {
        SignedMessageStruct struct = new SignedMessageStruct(ByteBuffer.wrap(content.getBytes()),
                ByteBuffer.wrap(sender.serialize()), ByteBuffer.wrap(signature.getBytes()));
        return Utils.serialize(struct);
    }
}
