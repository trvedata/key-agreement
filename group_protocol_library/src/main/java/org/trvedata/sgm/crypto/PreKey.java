package org.trvedata.sgm.crypto;

public class PreKey {
    /* package */ final IdentityKey identityKey;
    /* package */ final HPKEPublicKey signedPreKey;
    /* package */ final byte[] signedPreKeySig;
    /* package */ final HPKEPublicKey oneTimeKey;
    /* package */ final int id;

    public PreKey(IdentityKey identityKey, HPKEPublicKey signedPreKey, byte[] signedPreKeySig,
                  HPKEPublicKey oneTimeKey, int id) {
        this.identityKey = identityKey;
        this.signedPreKey = signedPreKey;
        this.signedPreKeySig = signedPreKeySig;
        this.oneTimeKey = oneTimeKey;
        this.id = id;
    }
}
