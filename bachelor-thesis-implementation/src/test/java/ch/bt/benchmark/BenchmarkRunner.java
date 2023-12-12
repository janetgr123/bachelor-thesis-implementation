package ch.bt.benchmark;

import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.VerboseMode;
import org.openjdk.jmh.runner.options.WarmupMode;

import java.util.concurrent.TimeUnit;

public class BenchmarkRunner {

    private static final int ITERATIONS = 1000;

    private static final int WARM_UPS = 10;
    public static void main(String[] args) throws Exception {
        Options opt =
                new OptionsBuilder()
                        .include(BenchmarkBaseline.class.getSimpleName())
                        .mode(Mode.AverageTime)
                        .timeUnit(TimeUnit.NANOSECONDS)
                        .warmupMode(WarmupMode.BULK_INDI)
                        .warmupForks(1)
                        .warmupIterations(WARM_UPS)
                        .forks(1)
                        .measurementIterations(ITERATIONS)
                        .resultFormat(ResultFormatType.CSV)
                        .result("src/test/resources/benchmark-results")
                        .verbosity(VerboseMode.NORMAL)
                        .output("src/test/resources/benchmark-logs")
                        .build();

        new Runner(opt).run();
    }
}
