package ch.bt.benchmark;

import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.*;

import java.util.concurrent.TimeUnit;

public class BenchmarkRunner {

    public static final int ITERATIONS = 10;

    public static final int WARM_UPS = 1;

    public static final int FORKS = 1;

    public static final int THREADS = 1;

    private static final String FOLDER = "src/test/resources/benchmark";

    private static Options createOptions(
            final String folder, final String method, final TimeUnit timeUnit) {
        final String path = String.valueOf(folder.charAt(0)).toLowerCase() + folder.substring(1);
        final String logs = String.join("", "benchmark-logs-", method, ".txt");
        final String results = String.join("", "benchmark-results-", method, ".csv");
        return new OptionsBuilder()
                .jvmArgsPrepend("-server")
                .include(folder + method + "[0-9]?")
                .mode(Mode.AverageTime)
                .timeUnit(timeUnit)
                .warmupMode(WarmupMode.INDI)
                .warmupForks(1)
                .warmupIterations(WARM_UPS)
                .forks(FORKS)
                .threads(THREADS)
                .measurementIterations(ITERATIONS)
                .resultFormat(ResultFormatType.CSV)
                .result(String.join("/", FOLDER, path, results))
                .verbosity(VerboseMode.EXTRA)
                .output(String.join("/", FOLDER, path, logs))
                .build();
    }

    public static void main(String[] args) throws RunnerException {
        new Runner(createOptions("Baseline", "BuildIndex", TimeUnit.MILLISECONDS)).run();
        new Runner(createOptions("Baseline", "Trapdoor", TimeUnit.NANOSECONDS)).run();
        new Runner(createOptions("Baseline", "Search", TimeUnit.NANOSECONDS)).run();
        new Runner(createOptions("VolumeHiding", "BuildIndex", TimeUnit.MILLISECONDS)).run();
        new Runner(createOptions("VolumeHiding", "Trapdoor", TimeUnit.NANOSECONDS)).run();
        new Runner(createOptions("VolumeHiding", "Search", TimeUnit.NANOSECONDS)).run();
        new Runner(createOptions("VolumeHidingOpt", "BuildIndex", TimeUnit.MILLISECONDS)).run();
        new Runner(createOptions("VolumeHidingOpt", "Trapdoor", TimeUnit.NANOSECONDS)).run();
        new Runner(createOptions("VolumeHidingOpt", "Search", TimeUnit.NANOSECONDS)).run();
        new Runner(createOptions("DpVolumeHiding", "BuildIndex", TimeUnit.MILLISECONDS)).run();
        new Runner(createOptions("DpVolumeHiding", "Trapdoor", TimeUnit.NANOSECONDS)).run();
        new Runner(createOptions("DpVolumeHiding", "Search", TimeUnit.NANOSECONDS)).run();
        new Runner(createOptions("DpVolumeHiding", "Trapdoor2", TimeUnit.NANOSECONDS)).run();
        new Runner(createOptions("DpVolumeHiding", "Search2", TimeUnit.NANOSECONDS)).run();
    }
}
