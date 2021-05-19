package org.trvedata.sgm;

import org.trvedata.sgm.communication.Client;
import org.trvedata.sgm.crypto.IdentityKey;
import org.trvedata.sgm.misc.Preconditions;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class ThreadedClient extends Client implements Runnable, DsgmClient.DsgmListener {

    public enum ClientRole {
        SENDER,
        RECIPIENT
    }

    private final LinkedBlockingQueue<NetworkMessageWithSender> mIncomingMessages = new LinkedBlockingQueue<>();

    /**
     * Stop procedure: interrupt + setting isRunning to 0
     */
    private final AtomicBoolean mIsRunning = new AtomicBoolean(true);

    /**
     * Total CPU time of this thread; will be set to a value != `-1` when the thread finishes
     */
    private volatile long mThreadCpuTime = -1L;

    /**
     * The client is expected to be in the "setup" phase until we have received (expected group size - 1) ack messages
     * plus the create message.
     */
    private final CountDownLatch mIsSetupLatch;
    private volatile boolean receivedCreate = false;

    /**
     * Used to wait until an operation has been handled by the client.
     */
    private final LinkedBlockingQueue<Operation> mFinishedOperations = new LinkedBlockingQueue<>();
    private CountDownLatch countExpectedMessagesLatch;

    private final DsgmClient mDsgmClient;
    private final String mName;
    private final ThreadSafeNetwork mNetwork;
    private final ClientRole mClientRole;

    private Thread mThread = null;

    public ThreadedClient(final DsgmClient dsgmClient, final ThreadSafeNetwork network, final ClientRole clientRole) {
        this(dsgmClient, network, null, clientRole);
    }

    public ThreadedClient(
            final DsgmClient dsgmClient,
            final ThreadSafeNetwork network,
            final Integer expectedGroupSize,
            final ClientRole clientRole) {
        mDsgmClient = dsgmClient;
        mDsgmClient.addListener(this);

        mName = network.idToName(dsgmClient.getIdentifier());
        mNetwork = network;
        mClientRole = clientRole;

        if (expectedGroupSize != null) {
            mIsSetupLatch = new CountDownLatch(expectedGroupSize - 1);
        } else {
            mIsSetupLatch = null;
        }
    }

    public ClientRole getRole() {
        return mClientRole;
    }

    public void start() {
        Preconditions.checkState(mThread == null, "ThreadedClient must only be started once");
        mThread = new Thread(this, "thread-" + mName.toLowerCase());
        mIsRunning.set(true);
        mThread.start();
    }

    public void stop() {
        mIsRunning.set(false);
        mThread.interrupt();
    }

    public void join() throws InterruptedException {
        mThread.join();
        mThread = null;
    }

    public void run() {
        init(mNetwork, mName);
        Utils.enableCpuTimeForCurrentThread();

        try {
            while (mIsRunning.get()) {
                final NetworkMessageWithSender incomingMessage = mIncomingMessages.poll(500, TimeUnit.MILLISECONDS);
                if (incomingMessage != null) {
                    synchronized (mDsgmClient) {
                        mDsgmClient.handleMessageFromNetwork(incomingMessage.senderIdentifier, incomingMessage.message);
                    }
                }
            }
        } catch (InterruptedException ignore) {
            // ignore
        } finally {
            mThreadCpuTime = Utils.getCpuTimeForCurrentThread();
        }
    }

    public long getCpuTime() {
        final long cpuTime = mThreadCpuTime;
        if (cpuTime == -1L) {
            throw new IllegalStateException("cpu time is only available when the thread has finished");
        }
        return cpuTime;
    }

    public void sendMessage(final String message) throws InterruptedException {
        if (countExpectedMessagesLatch != null) countExpectedMessagesLatch.countDown();
        synchronized (mDsgmClient) {
            mDsgmClient.send(message.getBytes());
        }
    }

    public void createGroup(Collection<IdentityKey> members) {
        if (members.contains(getIdentifier())) {
            members = new HashSet<>(members);
            members.remove(getIdentifier());
        }
        synchronized (mDsgmClient) {
            mDsgmClient.create(members);
        }
    }

    public void update() {
        synchronized (mDsgmClient) {
            mDsgmClient.update();
        }
    }

    public void removeMember(final ThreadedClient member) {
        synchronized (mDsgmClient) {
            mDsgmClient.remove((IdentityKey) member.getIdentifier());
        }
    }

    public void addMember(final ThreadedClient member) {
        synchronized (mDsgmClient) {
            mDsgmClient.add((IdentityKey) member.getIdentifier());
        }
    }

    public void waitUntilSetupFinished() throws InterruptedException {
        mIsSetupLatch.await();
    }

    /**
     * numMessages is number of calls to sendMessage and the listener methods below that we should wait for before
     * returning from waitUntilNextOperationFinished.
     */
    public void expectNextOperation(int numMessages) {
        mFinishedOperations.clear();
        countExpectedMessagesLatch = new CountDownLatch(numMessages);
    }

    public void clearNextOperation() {
        mFinishedOperations.clear();
    }

    public void waitUntilNextOperationFinished(final Operation expectedOperation) throws InterruptedException {
        final Operation actual = mFinishedOperations.take();
        if (actual != expectedOperation) {
            throw new IllegalStateException("Expected operation " + expectedOperation + " to finished, but got " + actual);
        }
        countExpectedMessagesLatch.await();
    }

    /**
     * Waits for the current operation to finish, for the operation's initiator, assuming that
     * expectNextOperation has been called with the number of acks to expect from recipients.
     * Unlike waitUntilNextOperationFinished, we don't verify the actual operation, since it
     * is necessarily correct, and the send methods don't result in calls to the listener methods
     * below (onUpdate, etc.).
     */
    public void waitUntilNextOperationFinishedSender() throws InterruptedException {
        countExpectedMessagesLatch.await();
    }

    @Override
    public String toString() {
        return mName;
    }

    @Override
    public Object getIdentifier() {
        return mDsgmClient.getIdentifier();
    }

    @Override
    public void handleMessageFromNetwork(final Object senderIdentifier, final byte[] message) {
        // add in thread-safe queue
        mIncomingMessages.add(new NetworkMessageWithSender(senderIdentifier, message));
    }

    @Override
    public void onIncomingMessage(IdentityKey sender, byte[] plaintext) {
        if (countExpectedMessagesLatch != null) countExpectedMessagesLatch.countDown();
        mFinishedOperations.add(Operation.MESSAGE);
        // Logger.d(mName, "Received message: " + new String(plaintext));
    }

    @Override
    public void onUpdate(IdentityKey sender, Object messageId) {
        if (countExpectedMessagesLatch != null) countExpectedMessagesLatch.countDown();
        mFinishedOperations.add(Operation.UPDATE);
        // Logger.d(mName, getName(sender) + " just updated");
    }

    @Override
    public void onAdd(IdentityKey adder, IdentityKey added, Object messageId) {
        if (countExpectedMessagesLatch != null) countExpectedMessagesLatch.countDown();
        if (mIsSetupLatch != null && !receivedCreate) {
            receivedCreate = true;
            mIsSetupLatch.countDown();
        }
        mFinishedOperations.add(Operation.ADD);
        // Logger.d(mName, getName(adder) + " just added " + getName(added));
    }

    @Override
    public void onRemove(IdentityKey remover, ArrayList<IdentityKey> removed, Object messageId) {
        if (countExpectedMessagesLatch != null) countExpectedMessagesLatch.countDown();
        mFinishedOperations.add(Operation.REMOVE);
        // Logger.d(mName, getName(remover) + " just removed " + Utils.identifierListToString(this, removed));
    }

    @Override
    public void onAck(IdentityKey acker, Object acked) {
        if (countExpectedMessagesLatch != null) countExpectedMessagesLatch.countDown();
        if (mIsSetupLatch != null) mIsSetupLatch.countDown();
    }

    class NetworkMessageWithSender {
        private final Object senderIdentifier;
        private final byte[] message;

        NetworkMessageWithSender(final Object senderIdentifier, final byte[] message) {
            this.senderIdentifier = senderIdentifier;
            this.message = message;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ThreadedClient client = (ThreadedClient) o;
        return mName.equals(client.mName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(mName);
    }
}
