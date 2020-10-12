package org.trvedata.sgm;

import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.trvedata.sgm.communication.SimpleNetwork;
import org.trvedata.sgm.crypto.InMemoryPreKeySource;

import static org.assertj.core.api.Assertions.assertThat;

public class DsgmClientFactoryTest {

    @Test
    public void testCreateClients_whenCreateFixedNumber_thenThatNumberCreated() throws Exception {
        final DsgmClientFactory.DgmClientFactoryResult factoryResult = DsgmClientFactory.createClients(new SimpleNetwork(),
                new InMemoryPreKeySource(), 10);
        assertThat(factoryResult.clients).hasSize(10);
        Assertions.assertThat(factoryResult.identityKeyToName).hasSize(10);
    }

    @Test
    public void testCreateClients_whenWithNamesArray_thenThatNumberCreated() throws Exception {
        final String[] names = {"alice", "bob"};
        final DsgmClientFactory.DgmClientFactoryResult factoryResult = DsgmClientFactory.createClients(new SimpleNetwork(),
                new InMemoryPreKeySource(), names);
        assertThat(factoryResult.clients).hasSize(names.length);
        Assertions.assertThat(factoryResult.identityKeyToName).hasSize(names.length);
    }

    @Test
    public void testCreateClients_whenWithNamesVarArgs_thenThatNumberCreated() throws Exception {
        final DsgmClientFactory.DgmClientFactoryResult factoryResult = DsgmClientFactory.createClients(new SimpleNetwork(),
                new InMemoryPreKeySource(), "alice", "bob");
        assertThat(factoryResult.clients).hasSize(2);
        Assertions.assertThat(factoryResult.identityKeyToName).hasSize(2);
    }

}
