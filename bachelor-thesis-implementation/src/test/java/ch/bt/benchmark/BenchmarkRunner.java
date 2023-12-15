package ch.bt.benchmark;

import ch.bt.TestUtils;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.bt.rc.RangeCoverUtils;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.*;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

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

    public static final int MAX_NUMBER_OF_DATA_SAMPLES = 100;
    private static final String FOLDER = "src/test/resources/benchmark";
    private static final Map<Integer, List<CustomRange>> ranges = new HashMap<>();

    private static Options createOptions(
            final String folder,
            final String method,
            final TimeUnit timeUnit,
            final int data,
            final String mode) {
        String clazz = String.valueOf(folder.charAt(0)).toUpperCase() + folder.substring(1);
        if (mode.equals("parallel")) {
            clazz = String.join("", clazz, "Par");
        }
        final String methodLower =
                String.valueOf(method.charAt(0)).toLowerCase() + method.substring(1);
        final String logs =
                String.join("", "benchmark-logs-", methodLower, String.valueOf(data), ".txt");
        final String results =
                String.join("", "benchmark-results-", methodLower, String.valueOf(data), ".csv");

        System.out.println("Preparing " + clazz + method);

        return new OptionsBuilder()
                .jvmArgsPrepend("-server")
                .include(clazz + method + "[0-9]?")
                .param("numberOfDataSamples", String.valueOf(data))
                .param(
                        "from",
                        ranges.get(data).stream()
                                .map(CustomRange::getMinimum)
                                .map(String::valueOf)
                                .toArray(String[]::new))
                .param(
                        "size",
                        ranges.get(data).stream()
                                .map(CustomRange::size)
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
                .result(String.join("/", FOLDER, folder, mode, "results", results))
                .verbosity(VerboseMode.EXTRA)
                .output(String.join("/", FOLDER, folder, mode, "logs", logs))
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

        for (int i = 10; i <= MAX_NUMBER_OF_DATA_SAMPLES; i *= 10) {
            root = RangeCoverUtils.getRoot(TestUtils.getDataFromDB(connection, i));
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
        int size = (int) (Math.random() * rootRange.size()) + 1;
        int from = (int) (Math.random() * max) + rootRange.getMinimum();
        return new CustomRange(from, Math.min(from + size - 1, max));
    }

    public static void main(String[] args) throws RunnerException, SQLException {
        Security.addProvider(new BouncyCastleFipsProvider());

        generateParams();

        final var folders =
                List.of("baseline", "volumeHiding", "volumeHidingOpt", "dpVolumeHiding");
        final var modes = List.of("sequential", "parallel");

        for (final var mode : modes) {
            System.out.println("Running " + mode + " range schemes.");
            for (final var folder : folders) {
                System.out.println("Folder " + folder);
                for (int i = 10; i <= MAX_NUMBER_OF_DATA_SAMPLES; i *= 10) {
                    System.out.println("Number of data samples " + i);

                    System.out.println("Running build index");
                    new Runner(createOptions(folder, "BuildIndex", TimeUnit.MILLISECONDS, i, mode))
                            .run();

                    System.out.println("Running trapdoor");
                    new Runner(createOptions(folder, "Trapdoor", TimeUnit.NANOSECONDS, i, mode))
                            .run();

                    System.out.println("Running search");
                    new Runner(createOptions(folder, "Search", TimeUnit.MILLISECONDS, i, mode))
                            .run();
                }
            }
        }
    }
}
