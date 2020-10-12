package org.trvedata.sgm.crypto;

import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;

public class InMemoryPreKeySource implements PreKeySource {
    private final ArrayListValuedHashMap<IdentityKey, PreKey> generatedPreKeys = new ArrayListValuedHashMap<>();

    public synchronized PreKeySecret registerUser(IdentityKeyPair identityKeyPair, int numOneTimeKeys) {
        PreKeySecret preKeySecret = new PreKeySecret(identityKeyPair);
        for (int i = 0; i < numOneTimeKeys; i++) {
            Pair<PreKeySecret, PreKey> preKeyPair = preKeySecret.generatePreKey();
            preKeySecret = preKeyPair.getLeft();
            generatedPreKeys.put(identityKeyPair.publicKey, preKeyPair.getRight());
        }
        return preKeySecret;
    }

    @Override
    public synchronized PreKey getPreKey(IdentityKey remote) {
        List<PreKey> list = generatedPreKeys.get(remote);
        if (list == null || list.isEmpty()) throw new IllegalArgumentException("No prekeys for " + remote);
        return list.remove(list.size() - 1);
    }
}
