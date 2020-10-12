package org.trvedata.sgm;

import org.trvedata.sgm.communication.Client;
import org.trvedata.sgm.crypto.IdentityKey;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.util.ArrayList;
import java.util.Random;

public final class Utils {

    private Utils() {
        // do not allow instantiation
    }

    public static <T> T randomChoice(final Random random, final ArrayList<T> arr) {
        return arr.get(random.nextInt(arr.size()));
    }

    public static <T> T randomChoiceExcept(final Random random, final ArrayList<T> arr, final T except) {
        final int posExcept = arr.indexOf(except);
        final int offset = random.nextInt(arr.size() - 1);
        return arr.get(offset >= posExcept ? offset + 1 : offset);
    }

    public static String identifierListToString(final Client client, final ArrayList<IdentityKey> list) {
        final ArrayList<String> strings = new ArrayList<>(list.size());
        for (IdentityKey it : list) strings.add(client.getName(it));
        return String.join(", ", strings);
    }

    public static void enableCpuTimeForCurrentThread() {
        final ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
        threadBean.setThreadCpuTimeEnabled(true);
    }

    public static long getCpuTimeForCurrentThread() {
        final ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
        return threadBean.getCurrentThreadCpuTime();
    }
}
