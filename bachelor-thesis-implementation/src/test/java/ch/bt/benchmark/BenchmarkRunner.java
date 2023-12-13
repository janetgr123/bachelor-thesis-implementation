package ch.bt.benchmark;

import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.*;

import java.util.concurrent.TimeUnit;

public class BenchmarkRunner {

    public static final int ITERATIONS = 2;

    public static final int WARM_UPS = 1;

    public static final int FORKS = 1;

    public static final int THREADS = 1;

    private static Options createOptions(
            final String folder, final String method, final TimeUnit timeUnit) {
        return new OptionsBuilder()
                .jvmArgsPrepend("-server")
                .include("[a-z, A-Z]" + method)
                .mode(Mode.AverageTime)
                .timeUnit(timeUnit)
                .warmupMode(WarmupMode.INDI)
                .warmupForks(1)
                .warmupIterations(WARM_UPS)
                .forks(FORKS)
                .threads(THREADS)
                .measurementIterations(ITERATIONS)
                .resultFormat(ResultFormatType.CSV)
                .result(
                        "src/test/resources/benchmark/"
                                + folder
                                + "/benchmark-results-"
                                + method
                                + ".csv")
                .verbosity(VerboseMode.EXTRA)
                .output(
                        "src/test/resources/benchmark/"
                                + folder
                                + "/benchmark-logs-"
                                + method
                                + ".txt")
                .build();
    }

    public static void main(String[] args) {
        new Runner(createOptions("baseline", "build-index", TimeUnit.MILLISECONDS));
        new Runner(createOptions("baseline", "trapdoor", TimeUnit.MICROSECONDS));
        new Runner(createOptions("baseline", "search", TimeUnit.MICROSECONDS));
    }
}
