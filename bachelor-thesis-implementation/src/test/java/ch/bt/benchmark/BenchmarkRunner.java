package ch.bt.benchmark;

import ch.bt.TestUtils;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.bt.rc.RangeCoverUtils;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.BenchmarkResult;
import org.openjdk.jmh.results.Result;
import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.*;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class BenchmarkRunner {
    public static int NUMBER_OF_SAMPLES = 3;
    public static final int ITERATIONS = 2;

    public static final int WARM_UPS = 1;

    public static final int FORKS = 1;

    public static final int THREADS = 1;

    private static final int MAX_NUMBER_OF_DATA_SAMPLES = 100;
    private static final String FOLDER = "src/test/resources/benchmark";
    private static final Map<Integer, List<CustomRange>> ranges = new HashMap<>();
    private static final List<Integer> data = new LinkedList<>();

    private static Options createOptions(
            final String folder,
            final String method,
            final TimeUnit timeUnit,
            final int data,
            final boolean parallel) {
        final String path = String.valueOf(folder.charAt(0)).toLowerCase() + folder.substring(1);
        final String logs = String.join("", "benchmark-logs-", method, ".txt");
        final String results = String.join("", "benchmark-results-", method, ".csv");
        final String subFolder = parallel ? "parallel" : "sequential";
        return new OptionsBuilder()
                .jvmArgsPrepend("-server")
                .include(folder + method + "[0-9]?")
                .param("numberOfDataSamples", String.valueOf(data))
                .param(
                        "from",
                        ranges.get(data).stream()
                                .map(CustomRange::getMinimum)
                                .map(String::valueOf)
                                .toArray(String[]::new))
                .param(
                        "to",
                        ranges.get(data).stream()
                                .map(CustomRange::getMaximum)
                                .map(String::valueOf)
                                .toArray(String[]::new))
                .mode(Mode.AverageTime)
                .timeUnit(timeUnit)
                .warmupMode(WarmupMode.INDI)
                .warmupForks(0)
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

    private static void generateParams() throws SQLException {
        PostgreSQLContainer<?> postgreSQLContainer =
                new PostgreSQLContainer<>(DockerImageName.parse("postgres:latest"))
                        .withReuse(true)
                        .withInitScript("init.sql");
        postgreSQLContainer.start();
        String jdbcUrl = postgreSQLContainer.getJdbcUrl();
        String username = postgreSQLContainer.getUsername();
        String password = postgreSQLContainer.getPassword();
        Connection connection = DriverManager.getConnection(jdbcUrl, username, password);
        BenchmarkUtils.addData(connection);
        Vertex root;

        for (int i = 1; i <= MAX_NUMBER_OF_DATA_SAMPLES; i *= 10) {
            root = RangeCoverUtils.getRoot(TestUtils.getDataFromDB(connection, i));
            data.add(i);
            final var rangesForData = new LinkedList<CustomRange>();
            for (int j = 0; j < NUMBER_OF_SAMPLES; j++) {
                rangesForData.add(generateRange(root));
            }
            ranges.put(i, rangesForData);
        }
    }

    private static CustomRange generateRange(final Vertex root) {
        final var rootRange = root.range();
        final int max = rootRange.getMaximum();
        int size = (int) (Math.random() * rootRange.size());
        int from = (int) (Math.random() * max) + rootRange.getMinimum();
        return new CustomRange(from, Math.min(from + size - 1, max));
    }

    public static void main(String[] args)
            throws RunnerException, SQLException, IOException, GeneralSecurityException {
        Security.addProvider(new BouncyCastleFipsProvider());

        generateParams();

        final var trapdoor =
                new ResultPrinter("trapdoor", "src/test/resources/benchmark/baseline/sequential");
        final var search =
                new ResultPrinter("search", "src/test/resources/benchmark/baseline/sequential");
        final var buildIndex =
                new ResultPrinter("buildIndex", "src/test/resources/benchmark/baseline/sequential");

        for (int i = 1; i <= MAX_NUMBER_OF_DATA_SAMPLES; i *= 10) {

            final var resultsBuildIndex =
                    new Runner(
                                    createOptions(
                                            "Baseline",
                                            "BuildIndex",
                                            TimeUnit.MILLISECONDS,
                                            i,
                                            false))
                            .run();

            final var scoresBuildIndex =
                    resultsBuildIndex.stream()
                            .map(RunResult::getAggregatedResult)
                            .map(BenchmarkResult::getPrimaryResult)
                            .map(Result::getScore)
                            .toList();

            if (scoresBuildIndex.size() == 1) {
                buildIndex.printToCsv(i, scoresBuildIndex.get(0));
            }

            // SEQUENTIAL RANGE SCHEMES
            // -------------------------------------------------------------------------------------------------

            // Baseline
            final var resultsTrapdoor =
                    new Runner(
                                    createOptions(
                                            "Baseline", "Trapdoor", TimeUnit.NANOSECONDS, i, false))
                            .run();
            final var scoresTrapdoor =
                    resultsTrapdoor.stream()
                            .map(RunResult::getAggregatedResult)
                            .map(BenchmarkResult::getPrimaryResult)
                            .map(Result::getScore)
                            .toList();

            if (scoresTrapdoor.size() == 1) {
                trapdoor.printToCsv(i, scoresTrapdoor.get(0));
            }

            final var resultsSearch =
                    new Runner(createOptions("Baseline", "Search", TimeUnit.MILLISECONDS, i, false))
                            .run();
            final var scoresSearch =
                    resultsSearch.stream()
                            .map(RunResult::getAggregatedResult)
                            .map(BenchmarkResult::getPrimaryResult)
                            .map(Result::getScore)
                            .toList();

            if (scoresSearch.size() == 1) {
                search.printToCsv(i, scoresSearch.get(0));
            }

            /*
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

             */
        }
        search.printer.close();
        trapdoor.printer.close();
        buildIndex.printer.close();
    }
}
