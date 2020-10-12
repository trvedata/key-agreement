package org.trvedata.sgm;

import org.trvedata.sgm.misc.Logger;
import picocli.CommandLine;

import java.util.concurrent.Callable;

import static picocli.CommandLine.Command;
import static picocli.CommandLine.Option;

@Command(
        description = "Runs a small local simulation with a group of clients",
        name = "cli_demo_local",
        mixinStandardHelpOptions = true,
        version = "0.1"
)
public class CliDemoLocal implements Callable<Integer> {

    @Option(names = {"-n", "--num-clients"}, defaultValue = "10", description = "Total number of clients in the simulation")
    public int mTotalNumberClients;

    @Option(names = {"-t", "--time"}, defaultValue = "5", description = "Total duration of the simulation in seconds")
    public int mDurationSeconds;

    public static void main(final String[] args) {
        final int exitCode = new CommandLine(new CliDemoLocal()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        final LocalSimulation simulation = new LocalSimulation(this);
        simulation.run();
        return 0;
    }
}