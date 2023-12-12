package ch.bt.benchmark;

import ch.bt.benchmark.baseline.BaselineBuildIndex;
import ch.bt.benchmark.baseline.BaselineTrapdoor;
import ch.bt.benchmark.volumeHiding.VolumeHidingBuildIndex;
import ch.bt.benchmark.volumeHiding.VolumeHidingTrapdoor;
import ch.bt.benchmark.volumeHidingOpt.VolumeHidingOptBuildIndex;
import ch.bt.benchmark.volumeHidingOpt.VolumeHidingOptTrapdoor;

import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.VerboseMode;
import org.openjdk.jmh.runner.options.WarmupMode;

import java.util.Collection;
import java.util.concurrent.TimeUnit;

public class BenchmarkRunner {

    public static final int ITERATIONS = 2;

    public static final int WARM_UPS = 1;

    public static final int FORKS = 1;

    public static final int THREADS = 1;

    public static void main(String[] args) throws Exception {
        Options opt =
                new OptionsBuilder()
                        .jvmArgsPrepend("-server")
                        .include(BaselineBuildIndex.class.getSimpleName())
                        .include(VolumeHidingBuildIndex.class.getSimpleName())
                        .include(VolumeHidingOptBuildIndex.class.getSimpleName())
                        .include(BaselineTrapdoor.class.getSimpleName())
                        .include(VolumeHidingTrapdoor.class.getSimpleName())
                        .include(VolumeHidingOptTrapdoor.class.getSimpleName())
                        .mode(Mode.AverageTime)
                        .timeUnit(TimeUnit.MILLISECONDS)
                        .warmupMode(WarmupMode.BULK_INDI)
                        .warmupForks(1)
                        .warmupIterations(WARM_UPS)
                        .forks(FORKS)
                        .threads(THREADS)
                        .measurementIterations(ITERATIONS)
                        .resultFormat(ResultFormatType.CSV)
                        .result("src/test/resources/benchmark-results.csv")
                        .verbosity(VerboseMode.EXTRA)
                        .output("src/test/resources/benchmark-logs.txt")
                        .build();

        Collection<RunResult> result = new Runner(opt).run();
        System.out.println(result);
    }
}
