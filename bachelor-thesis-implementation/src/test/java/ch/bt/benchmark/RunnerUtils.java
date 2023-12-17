package ch.bt.benchmark;

import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.VerboseMode;
import org.openjdk.jmh.runner.options.WarmupMode;

import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

public class RunnerUtils {

    public static Options createOptionsForSearch(
            final String folder, final String mode, final int dataSize) {
        final var potenitalStep = dataSize / 20;
        final var step = potenitalStep == 0 ? 1 : potenitalStep;
        final var ranges =
                IntStream.iterate(step, i -> i <= dataSize, i -> i + step)
                        .mapToObj(String::valueOf)
                        .toArray(String[]::new);
        String clazz = String.valueOf(folder.charAt(0)).toUpperCase() + folder.substring(1);
        if (mode.equals("parallel")) {
            clazz = String.join("", clazz, "Par");
        }
        final String logs = String.join("", "benchmark-logs-", "search", ".txt");
        final String results = String.join("", "benchmark-results-", "search", ".csv");

        System.out.println("Preparing " + clazz + " trapdoor");

        return new OptionsBuilder()
                .jvmArgsPrepend("-server")
                .include(Search.class.getName())
                .param("numberOfDataSamples", String.valueOf(dataSize))
                .param("rangeSize", ranges)
                .param("type", folder)
                .mode(Mode.AverageTime)
                .timeUnit(TimeUnit.MILLISECONDS)
                .warmupMode(WarmupMode.INDI)
                .warmupIterations(BenchmarkSettings.WARM_UPS)
                .measurementIterations(BenchmarkSettings.NUMBER_OF_QUERIES)
                .forks(BenchmarkSettings.FORKS)
                .resultFormat(ResultFormatType.CSV)
                .result(String.join("/", BenchmarkSettings.FOLDER, results))
                .verbosity(VerboseMode.EXTRA)
                .output(String.join("/", BenchmarkSettings.FOLDER, logs))
                .build();
    }

    public static Options createOptionsForTrapdoor(
            final String folder, final String mode, final int dataSize) {
        final var potenitalStep = dataSize / 20;
        final var step = potenitalStep == 0 ? 1 : potenitalStep;
        final var ranges =
                IntStream.iterate(step, i -> i <= dataSize, i -> i + step)
                        .mapToObj(String::valueOf)
                        .toArray(String[]::new);
        String clazz = String.valueOf(folder.charAt(0)).toUpperCase() + folder.substring(1);
        if (mode.equals("parallel")) {
            clazz = String.join("", clazz, "Par");
        }
        final String logs = String.join("", "benchmark-logs-", "trapdoor", ".txt");
        final String results = String.join("", "benchmark-results-", "trapdoor", ".csv");

        System.out.println("Preparing " + clazz + " trapdoor");

        return new OptionsBuilder()
                .jvmArgsPrepend("-server")
                .include(Trapdoor.class.getName())
                .param("numberOfDataSamples", String.valueOf(dataSize))
                .param("rangeSize", ranges)
                .param("type", folder)
                .mode(Mode.AverageTime)
                .timeUnit(TimeUnit.MILLISECONDS)
                .warmupMode(WarmupMode.INDI)
                .warmupIterations(BenchmarkSettings.WARM_UPS)
                .measurementIterations(BenchmarkSettings.NUMBER_OF_QUERIES)
                .forks(BenchmarkSettings.FORKS)
                .resultFormat(ResultFormatType.CSV)
                .result(String.join("/", BenchmarkSettings.FOLDER, results))
                .verbosity(VerboseMode.EXTRA)
                .output(String.join("/", BenchmarkSettings.FOLDER, logs))
                .build();
    }

    public static Options createOptionsForBuildIndex(final String folder, final String mode) {
        String clazz = String.valueOf(folder.charAt(0)).toUpperCase() + folder.substring(1);
        if (mode.equals("parallel")) {
            clazz = String.join("", clazz, "Par");
        }
        final String logs = String.join("", "benchmark-logs-", "buildIndex", ".txt");
        final String results = String.join("", "benchmark-results-", "buildIndex", ".csv");

        System.out.println("Preparing " + clazz + " build index");

        return new OptionsBuilder()
                .jvmArgsPrepend("-server")
                .include(BuildIndex.class.getName())
                .param(
                        "numberOfDataSamples",
                        IntStream.iterate(
                                        10,
                                        i -> i <= BenchmarkSettings.MAX_NUMBER_OF_DATA_SAMPLES,
                                        i -> 10 * i)
                                .mapToObj(String::valueOf)
                                .toArray(String[]::new))
                .param("type", folder)
                .mode(Mode.AverageTime)
                .timeUnit(TimeUnit.MILLISECONDS)
                .warmupMode(WarmupMode.INDI)
                .warmupIterations(BenchmarkSettings.WARM_UPS)
                .measurementIterations(BenchmarkSettings.NUMBER_OF_ITERATIONS_BUILD_INDEX)
                .forks(BenchmarkSettings.FORKS)
                .resultFormat(ResultFormatType.CSV)
                .result(String.join("/", BenchmarkSettings.FOLDER, results))
                .verbosity(VerboseMode.EXTRA)
                .output(String.join("/", BenchmarkSettings.FOLDER, logs))
                .build();
    }
}
