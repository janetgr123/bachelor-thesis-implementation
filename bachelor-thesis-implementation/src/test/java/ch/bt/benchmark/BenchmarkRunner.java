package ch.bt.benchmark;

import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.profile.*;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.VerboseMode;
import org.openjdk.jmh.runner.options.WarmupMode;

import java.util.concurrent.TimeUnit;

public class BenchmarkRunner {

    public static final int ITERATIONS = 10;

    public static final int WARM_UPS = 5;

    public static void main(String[] args) throws Exception {
        Options opt =
                new OptionsBuilder()
                        .jvmArgsPrepend("-server")
                        // .addProfiler(GCProfiler.class)
                        .addProfiler(LinuxPerfProfiler.class)
                        .include(BaselineBuildIndex.class.getSimpleName())
                        .include(VolumeHidingRSBuildIndex.class.getSimpleName())
                        .mode(Mode.AverageTime)
                        .timeUnit(TimeUnit.MILLISECONDS)
                        .warmupMode(WarmupMode.BULK_INDI)
                        //.warmupForks(2)
                        //.warmupIterations(WARM_UPS)
                        .forks(2)
                        //.measurementIterations(ITERATIONS)
                        .resultFormat(ResultFormatType.CSV)
                        .result("src/test/resources/benchmark-results.csv")
                        .verbosity(VerboseMode.EXTRA)
                        .output("src/test/resources/benchmark-logs.txt")
                        .build();

        new Runner(opt).run();
    }
}
