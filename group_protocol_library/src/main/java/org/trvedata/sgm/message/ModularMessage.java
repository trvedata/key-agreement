package org.trvedata.sgm.message;

import org.apache.thrift.TException;
import org.trvedata.sgm.Orderer;
import org.trvedata.sgm.SignatureProtocol;
import org.trvedata.sgm.misc.ByteHolder;
import org.trvedata.sgm.misc.Utils;

import java.nio.ByteBuffer;

public class ModularMessage {
    public final boolean isDcgka;
    public final boolean isWelcome;
    public final byte[] content; // DcgkaProtocol.ControlMessage or application ciphertext
    public final Orderer.OrderInfo orderInfo;
    public SignatureProtocol.Update signatureUpdate; // wrapper around null if not set

    public ModularMessage(boolean isDcgka, boolean isWelcome, byte[] content, Orderer.OrderInfo orderInfo) {
        this.isDcgka = isDcgka;
        this.isWelcome = isWelcome;
        this.content = content;
        this.orderInfo = orderInfo;
        this.signatureUpdate = SignatureProtocol.Update.of(null);
        if (content == null) throw new IllegalArgumentException("content is null");
        if (orderInfo == null) {
            throw new IllegalArgumentException("orderInfo is null (did you mean OrderInfo.of(null)?)");
        }
    }

    public ModularMessage(Serialized serialized) {
        ModularMessageStruct struct = new ModularMessageStruct();
        try {
            Utils.deserialize(struct, serialized.getBytes());
        } catch (TException exc) {
            throw new IllegalArgumentException("Failed to deserialize ModularMessageStruct", exc);
        }
        this.isDcgka = struct.isDcgka();
        this.isWelcome = struct.isWelcome();
        this.content = struct.getContent();
        this.orderInfo = Orderer.OrderInfo.of(struct.getOrderInfo());
        this.signatureUpdate = SignatureProtocol.Update.of(struct.getSignatureUpdate());
    }

    public Serialized serialize() {
        ModularMessageStruct struct = new ModularMessageStruct(isDcgka, isWelcome,
                ByteBuffer.wrap(content));
        if (orderInfo.getBytes() != null) {
            struct.setOrderInfo(orderInfo.getBytes());
        }
        if (signatureUpdate.getBytes() != null) {
            struct.setSignatureUpdate(signatureUpdate.getBytes());
        }
        return Serialized.of(Utils.serialize(struct));

    }

    public static class Serialized extends ByteHolder {
        public Serialized(byte[] bytes) {
            super(bytes);
        }

        public static Serialized of(byte[] bytes) {
            return new Serialized(bytes);
        }
    }
}
