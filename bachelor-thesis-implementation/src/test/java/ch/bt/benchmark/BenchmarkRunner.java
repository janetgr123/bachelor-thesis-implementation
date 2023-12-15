package ch.bt.benchmark;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;

import java.security.Security;
import java.sql.SQLException;
import java.util.List;
import java.util.stream.IntStream;

public class BenchmarkRunner {

    private static final boolean RUN_BUILD_INDEX_BENCHMARKS = false;
    private static final boolean RUN_TRAPDOOR_BENCHMARKS = true;
    private static final boolean RUN_SEARCH_BENCHMARKS = true;

    /*
    Running a Runner starts a parametrized benchmark run.
    A benchmark run runs isolated in a VM on a fresh JVM handled by JMH.
    It runs numberOfIterations * numberOfValuesParam1 * numberOfValuesParam2 * ... times.
    E.g. numberOfIterationsBuildIndex * dataSizes * scheme types * modes.
     */
    public static void main(String[] args) throws RunnerException, SQLException {
        System.out.println("STARTING BENCHMARKS");
        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");

        Security.addProvider(new BouncyCastleFipsProvider());

        final var folders =
                List.of("baseline", "volumeHiding"); // , "volumeHidingOpt", "dpVolumeHiding");
        final var modes = List.of("sequential");
        // List.of("sequential", "parallel");

        /*
        BUILD INDEX
         */
        if (RUN_BUILD_INDEX_BENCHMARKS) {
            for (final var mode : modes) {
                System.out.println();
                System.out.println("Running " + mode + " range schemes.");
                for (final var folder : folders) {
                    System.out.println();
                    System.out.println("Range scheme type: " + folder);

                    System.out.println();
                    System.out.println("Running build index for " + folder + " " + mode);
                    new Runner(BenchmarkUtils.createOptionsForBuildIndex(folder, mode)).run();
                }
            }
        } else {
            System.out.println();
            System.out.println("SKIPPING BUILD INDEX");
            System.out.println();
        }

        /*
        TRAPDOOR
         */
        if (RUN_TRAPDOOR_BENCHMARKS) {
            for (final var mode : modes) {
                System.out.println();
                System.out.println("Running " + mode + " range schemes.");
                for (final var folder : folders) {
                    System.out.println();
                    System.out.println("Range scheme type: " + folder);
                    IntStream.iterate(
                                    10,
                                    i -> i <= BenchmarkSettings.MAX_NUMBER_OF_DATA_SAMPLES,
                                    i -> 10 * i)
                            .forEach(
                                    dataSize -> {
                                        System.out.println();
                                        System.out.println(
                                                "Run trapdoor for data size " + dataSize);
                                        try {
                                            new Runner(
                                                            BenchmarkUtils.createOptionsForTrapdoor(
                                                                    folder, mode, dataSize))
                                                    .run();
                                        } catch (RunnerException e) {
                                            throw new RuntimeException(e);
                                        }
                                    });
                }
            }

        } else {
            System.out.println();
            System.out.println("SKIPPING TRAPDOOR");
            System.out.println();
        }

         /*
        TRAPDOOR
         */
        if (RUN_SEARCH_BENCHMARKS) {
            for (final var mode : modes) {
                System.out.println();
                System.out.println("Running " + mode + " range schemes.");
                for (final var folder : folders) {
                    System.out.println();
                    System.out.println("Range scheme type: " + folder);
                    IntStream.iterate(
                                    10,
                                    i -> i <= BenchmarkSettings.MAX_NUMBER_OF_DATA_SAMPLES,
                                    i -> 10 * i)
                            .forEach(
                                    dataSize -> {
                                        System.out.println();
                                        System.out.println(
                                                "Run search for data size " + dataSize);
                                        try {
                                            new Runner(
                                                    BenchmarkUtils.createOptionsForSearch(
                                                            folder, mode, dataSize))
                                                    .run();
                                        } catch (RunnerException e) {
                                            throw new RuntimeException(e);
                                        }
                                    });
                }
            }

        } else {
            System.out.println();
            System.out.println("SKIPPING SEARCH");
            System.out.println();
        }

        System.out.println();
        System.out.println("DONE");
    }
}
