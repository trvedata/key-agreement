package org.trvedata.sgm.misc;

import java.io.PrintStream;

public class Logger {

    public enum Level {
        DEBUG(0, 'D'),
        INFO(1, 'I'),
        WARN(2, 'W');

        private final int level;
        private final char identifier;

        Level(final int level, final char identifier) {
            this.level = level;
            this.identifier = identifier;
        }
    }

    private static Long startTimeNs = System.nanoTime(); // nano time is guaranteed to be monotonic
    private static Level loggingLevel = Level.DEBUG;

    public static void d(final String tag, final String message) {
        log(Level.DEBUG, tag, message);
    }

    public static void i(final String tag, final String message) {
        log(Level.INFO, tag, message);
    }

    public static void w(final String tag, final String message) {
        log(Level.WARN, tag, message);
    }

    public static synchronized void log(final Level level, final String tag, final String message) {
        if (level.level < loggingLevel.level) {
            return;
        }

        final PrintStream printer = (level == Level.WARN) ? System.err : System.out;
        printer.printf("%06d [%c] %18s: %s%n", getDeltaTimeMs(), level.identifier, tag, message);
        printer.flush();
    }

    public static void setLoggingLevel(final Level level) {
        Logger.loggingLevel = level;
    }

    private static long getDeltaTimeMs() {
        return (System.nanoTime() - startTimeNs) / 1_000_000; // 10^-9s to 10^-3s
    }
}
