package ch.bt.benchmark;

import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.*;

import java.util.concurrent.TimeUnit;

public class BenchmarkRunner {

    public static final int ITERATIONS = 2;

    public static final int WARM_UPS = 1;

    public static final int FORKS = 1;

    public static final int THREADS = 1;

    private static final String FOLDER = "src/test/resources/benchmark";

    private static Options createOptions(
            final String folder,
            final String method,
            final TimeUnit timeUnit,
            final boolean parallel) {
        final String path = String.valueOf(folder.charAt(0)).toLowerCase() + folder.substring(1);
        final String logs = String.join("", "benchmark-logs-", method, ".txt");
        final String results = String.join("", "benchmark-results-", method, ".csv");
        final String subFolder = parallel ? "parallel" : "sequential";
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
                .result(String.join("/", FOLDER, path, subFolder, results))
                .verbosity(VerboseMode.EXTRA)
                .output(String.join("/", FOLDER, path, subFolder, logs))
                .build();
    }

    public static void main(String[] args) throws RunnerException {

        // SEQUENTIAL RANGE SCHEMES
        // -------------------------------------------------------------------------------------------------

        // Baseline
        new Runner(createOptions("Baseline", "BuildIndex", TimeUnit.MILLISECONDS, false)).run();
        new Runner(createOptions("Baseline", "Trapdoor", TimeUnit.NANOSECONDS, false)).run();
        new Runner(createOptions("Baseline", "Search", TimeUnit.MILLISECONDS, false)).run();

        // Volume Hiding
        new Runner(createOptions("VolumeHiding", "BuildIndex", TimeUnit.MILLISECONDS, false)).run();
        new Runner(createOptions("VolumeHiding", "Trapdoor", TimeUnit.NANOSECONDS, false)).run();
        new Runner(createOptions("VolumeHiding", "Search", TimeUnit.MILLISECONDS, false)).run();

        // Volume Hiding Optimised
        new Runner(createOptions("VolumeHidingOpt", "BuildIndex", TimeUnit.MILLISECONDS, false))
                .run();
        new Runner(createOptions("VolumeHidingOpt", "Trapdoor", TimeUnit.NANOSECONDS, false)).run();
        new Runner(createOptions("VolumeHidingOpt", "Search", TimeUnit.MILLISECONDS, false)).run();

        // Differentially Private Volume Hiding
        new Runner(createOptions("DpVolumeHiding", "BuildIndex", TimeUnit.MILLISECONDS, false))
                .run();
        new Runner(createOptions("DpVolumeHiding", "Trapdoor", TimeUnit.NANOSECONDS, false)).run();
        new Runner(createOptions("DpVolumeHiding", "Search", TimeUnit.MILLISECONDS, false)).run();
        new Runner(createOptions("DpVolumeHiding", "Trapdoor2", TimeUnit.NANOSECONDS, false)).run();
        new Runner(createOptions("DpVolumeHiding", "Search2", TimeUnit.MILLISECONDS, false)).run();

        // -------------------------------------------------------------------------------------------------
        // PARALLEL RANGE SCHEMES
        // -------------------------------------------------------------------------------------------------

        // Baseline
        new Runner(createOptions("Baseline", "BuildIndexPar", TimeUnit.MILLISECONDS, true)).run();
        new Runner(createOptions("Baseline", "TrapdoorPar", TimeUnit.NANOSECONDS, true)).run();
        new Runner(createOptions("Baseline", "SearchPar", TimeUnit.MILLISECONDS, true)).run();

        // Volume Hiding
        new Runner(createOptions("VolumeHiding", "BuildIndexPar", TimeUnit.MILLISECONDS, true))
                .run();
        new Runner(createOptions("VolumeHiding", "TrapdoorPar", TimeUnit.NANOSECONDS, true)).run();
        new Runner(createOptions("VolumeHiding", "SearchPar", TimeUnit.MILLISECONDS, true)).run();

        // Volume Hiding Optimised
        new Runner(createOptions("VolumeHidingOpt", "BuildIndexPar", TimeUnit.MILLISECONDS, true))
                .run();
        new Runner(createOptions("VolumeHidingOpt", "TrapdoorPar", TimeUnit.NANOSECONDS, true))
                .run();
        new Runner(createOptions("VolumeHidingOpt", "SearchPar", TimeUnit.MILLISECONDS, true))
                .run();

        // Differentially Private Volume Hiding
        new Runner(createOptions("DpVolumeHiding", "BuildIndexPar", TimeUnit.MILLISECONDS, true))
                .run();
        new Runner(createOptions("DpVolumeHiding", "TrapdoorPar", TimeUnit.NANOSECONDS, true))
                .run();
        new Runner(createOptions("DpVolumeHiding", "SearchPar", TimeUnit.MILLISECONDS, true)).run();
        new Runner(createOptions("DpVolumeHiding", "TrapdoorPar2", TimeUnit.NANOSECONDS, true))
                .run();
        new Runner(createOptions("DpVolumeHiding", "SearchPar2", TimeUnit.MILLISECONDS, true))
                .run();
    }
}
