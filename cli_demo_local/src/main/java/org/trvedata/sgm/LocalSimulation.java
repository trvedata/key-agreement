package org.trvedata.sgm;

import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.crypto.IdentityKeyPair;
import org.trvedata.sgm.crypto.InMemoryPreKeySource;
import org.trvedata.sgm.crypto.PreKeySecret;
import org.trvedata.sgm.misc.Logger;

import java.util.ArrayList;
import java.util.Locale;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

public class LocalSimulation {

    public static final String TAG = "Simulation";

    public static final double LIKELIHOOD_MESSAGE = 0.2;
    public static final double LIKELIHOOD_REMOVE = 0.05;
    public static final double LIKELIHOOD_ADD = 0.05;

    private final CliDemoLocal mArgs;

    public LocalSimulation(final CliDemoLocal args) {
        mArgs = args;
    }

    public void run() throws InterruptedException {
        final ThreadSafeNetwork network = new ThreadSafeNetwork();
        InMemoryPreKeySource preKeySource = new InMemoryPreKeySource();
        final ArrayList<ThreadedClient> clients = createThreadedClients(network, preKeySource);
        final AtomicInteger sClientIdCounter = new AtomicInteger(0);
        final Random random = new Random();

        // start
        Logger.i(TAG, "Start");
        for (ThreadedClient client : clients) client.start();

        // run
        final ArrayList<IdentityKey> memberKeys = new ArrayList<>();
        for (final ThreadedClient client : clients) memberKeys.add((IdentityKey) client.getIdentifier());
        clients.get(0).createGroup(memberKeys);

        for (ThreadedClient client : clients) client.waitUntilSetupFinished();
        Logger.i(TAG, " --- END OF SETUP PHASE ---");

        final int deltaMs = 100;
        for (int t = 0; t < mArgs.mDurationSeconds * 1000; t += deltaMs) {
            Logger.i(TAG, String.format((Locale) null,
                    "Progress %.1f seconds of %.1f seconds; group size=%d", t / 1000f, (float) mArgs.mDurationSeconds, clients.size()));

            if (random.nextDouble() < LIKELIHOOD_MESSAGE) {
                final ThreadedClient sender = Utils.randomChoice(random, clients);
                Logger.i(TAG, "Sending message from " + sender);

                sender.sendMessage("Hello World");
            }

            if (random.nextDouble() < LIKELIHOOD_REMOVE) {
                if (clients.size() < 2) {
                    Logger.i(TAG, "Group size must be at least 2 for a remove");
                } else {
                    final ThreadedClient remover = Utils.randomChoice(random, clients);
                    final ThreadedClient toBeRemoved = Utils.randomChoiceExcept(random, clients, remover);
                    Logger.i(TAG, remover + " removes " + toBeRemoved);

                    remover.removeMember(toBeRemoved);
                    clients.remove(toBeRemoved);
                }
            }

            if (random.nextDouble() < LIKELIHOOD_ADD) {
                final IdentityKeyPair toAddKeyPair = IdentityKey.generateKeyPair();
                final PreKeySecret toAddPreKeySecret = preKeySource.registerUser(toAddKeyPair, clients.size() + 1);

                final ThreadedClient adder = Utils.randomChoice(random, clients);
                final DsgmClient dsgmClient = new DsgmClient(network, toAddPreKeySecret, preKeySource,
                        "LateClient_" + sClientIdCounter.getAndIncrement(), toAddKeyPair, createClientImplementation());
                final ThreadedClient toBeAdded = new ThreadedClient(dsgmClient, network, ThreadedClient.ClientRole.RECIPIENT);
                Logger.i(TAG, adder + " adds " + toBeAdded);

                clients.add(toBeAdded);
                toBeAdded.start();

                adder.addMember(toBeAdded);
            }

            Thread.sleep(deltaMs);
        }

        // stop
        Logger.i("Simulation", "Stopping...");
        for (ThreadedClient client : clients) {
            client.stop();
            client.join();
        }
        Logger.i("Simulation", "Finished");
    }

    private DsgmClient.DgmClientImplementationConfiguration createClientImplementation() {
        return new DsgmClient.DgmClientImplementationConfiguration(DsgmClient.DcgkaChoice.FULL, true, true, true);
    }

    private ArrayList<ThreadedClient> createThreadedClients(final ThreadSafeNetwork network,
                                                            final InMemoryPreKeySource preKeySource) {
        final int numClients = mArgs.mTotalNumberClients;
        final DsgmClientFactory.DgmClientFactoryResult factoryResult = DsgmClientFactory.createClients(network, preKeySource, numClients);
        final ArrayList<ThreadedClient> clients = new ArrayList<>(numClients);
        for (int i = 0; i < numClients; i++) {
            clients.add(new ThreadedClient(factoryResult.clients[i], network, numClients, i == 0 ? ThreadedClient.ClientRole.SENDER : ThreadedClient.ClientRole.RECIPIENT));
        }
        return clients;
    }

}
