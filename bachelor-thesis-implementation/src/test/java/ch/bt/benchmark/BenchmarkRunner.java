package ch.bt.benchmark;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;

import java.io.FileNotFoundException;
import java.security.Security;
import java.util.List;
import java.util.stream.IntStream;

public class BenchmarkRunner {

    private static final List<String> HELPER_FILES =
            List.of("encryptedIndex-build-index.csv", "root-build-index.csv", "token-trapdoor.csv");

    /*
    Running a Runner starts a parametrized benchmark run.
    A benchmark run runs isolated in a VM on a fresh JVM handled by JMH.
    It runs numberOfIterations * numberOfValuesParam1 * numberOfValuesParam2 * ... times.
    E.g. numberOfIterationsBuildIndex * dataSizes * scheme types * modes.
    Since a JMH benchmark run is isolated, the emm state and other params need to be written into files
    and read in again. This generates a bit of overhead for the experiment. However, the I/O operations
    are run in the setup methods of the benchmarks and therefore do not dilute the measurements.
     */
    public static void main(String[] args) throws RunnerException, FileNotFoundException {
        //final var file = new File(String.join("/", BenchmarkSettings.FOLDER, "console-logs.txt"));
        //System.setOut(new PrintStream(new FileOutputStream(file)));

        BenchmarkUtils.deleteHelperFile("results-build-index.csv");
        BenchmarkUtils.deleteHelperFile("results-search.csv");

        System.out.println("STARTING BENCHMARKS");
        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");

        Security.addProvider(new BouncyCastleFipsProvider());

        final var folders = List.of("volumeHiding");
        // List.of("baseline", "volumeHiding", "volumeHidingOpt", "dpVolumeHiding");
        final var modes = List.of("sequential");
        // List.of("sequential", "parallel");

        /*
        BUILD INDEX
         */
        for (final var mode : modes) {
            System.out.println();
            System.out.println("Running " + mode + " range schemes.");
            for (final var folder : folders) {
                HELPER_FILES.forEach(BenchmarkUtils::deleteHelperFile);

                System.out.println();
                System.out.println("Range scheme type: " + folder);

                System.out.println();
                System.out.println("Running build index for " + folder + " " + mode);
                new Runner(RunnerUtils.createOptionsForBuildIndex(folder, mode)).run();

                IntStream.iterate(
                                10,
                                i -> i <= BenchmarkSettings.MAX_NUMBER_OF_DATA_SAMPLES,
                                i -> 10 * i)
                        .forEach(
                                dataSize -> {
                                    /*
                                    TRAPDOOR
                                     */
                                    System.out.println();
                                    System.out.println("Run trapdoor for data size " + dataSize);

                                    try {
                                        new Runner(
                                                        RunnerUtils.createOptionsForTrapdoor(
                                                                folder, mode, dataSize))
                                                .run();
                                    } catch (RunnerException e) {
                                        throw new RuntimeException(e);
                                    }
                                    /*
                                    SEARCH
                                     */
                                    System.out.println();
                                    System.out.println("Run search for data size " + dataSize);

                                    try {
                                        new Runner(
                                                        RunnerUtils.createOptionsForSearch(
                                                                folder, mode, dataSize))
                                                .run();
                                    } catch (RunnerException e) {
                                        throw new RuntimeException(e);
                                    }
                                });
            }
        }

        System.out.println();
        System.out.println("DONE");
    }
}
