package org.trvedata.sgm;

import picocli.CommandLine;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.util.concurrent.Callable;

import static picocli.CommandLine.Command;
import static picocli.CommandLine.Option;

@Command(
        description = "Runs the simulation for gathering stats for the evaluation",
        name = "cli_evaluation",
        mixinStandardHelpOptions = true,
        version = "0.1"
)
public class CliEvaluation implements Callable<Integer> {

    @Option(names = {"-o", "--output-folder"}, description = "Output CSV folder (must exist)")
    public File csvOutputFolder;

    @Option(names = {"-i", "--iterations"}, defaultValue = "10", description = "Number of iterations for each test scenario")
    public int iterations;

    public static void main(final String[] args) {
        final ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
        if (!threadBean.isThreadCpuTimeSupported()) {
            System.out.println("Thread CPU time is not supported by this JVM");
            System.exit(1);
        }

        final int exitCode = new CommandLine(new CliEvaluation()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        final EvaluationSimulation evaluationSimulation = new EvaluationSimulation(this);
        evaluationSimulation.run();
        return 0;
    }
}