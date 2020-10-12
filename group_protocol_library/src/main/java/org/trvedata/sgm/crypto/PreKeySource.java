package org.trvedata.sgm.crypto;

public interface PreKeySource {
    PreKey getPreKey(IdentityKey remote);
}
