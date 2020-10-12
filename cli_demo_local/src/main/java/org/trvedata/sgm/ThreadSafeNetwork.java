package org.trvedata.sgm;

import org.trvedata.sgm.communication.Client;
import org.trvedata.sgm.communication.Network;
import org.trvedata.sgm.communication.SimpleNetwork;

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

public class ThreadSafeNetwork implements Network {

    private final ReentrantLock lock = new ReentrantLock();
    private final Network mNetwork;

    // For the `sent` traffic, broadcast messages are counted only once
    private final AtomicLong mSentBytes = new AtomicLong(0);

    public ThreadSafeNetwork() {
        mNetwork = new SimpleNetwork();
    }

    @Override
    public void connect(final Client client, final String name) {
        lock.lock();
        try {
            mNetwork.connect(client, name);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void send(final Client sender, final Object recipientIdentifier, final byte[] message) {
        mSentBytes.addAndGet(message.length);
        lock.lock();
        try {
            mNetwork.send(sender, recipientIdentifier, message);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void broadcast(final Client sender, final byte[] message) {
        mSentBytes.addAndGet(message.length); // only once
        lock.lock();
        try {
            mNetwork.broadcast(sender, message);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public String idToName(Object identifier) {
        lock.lock();
        try {
            return mNetwork.idToName(identifier);
        } finally {
            lock.unlock();
        }
    }


    @Override
    public int numClients() {
        return mNetwork.numClients();
    }

    public long getSentBytes() {
        return mSentBytes.get();
    }
}
