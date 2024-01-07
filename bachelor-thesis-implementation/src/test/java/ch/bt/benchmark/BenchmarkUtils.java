package ch.bt.benchmark;

import ch.bt.TestUtils;
import ch.bt.emm.EMM;
import ch.bt.genericRs.*;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.PairLabelCiphertext;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.bt.rc.BestRangeCover;
import ch.bt.rc.RangeCoverUtils;

import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.*;

/**
 * This class is a collection of static helper methods for the benchmark runs. The time is measured
 * using System.nanoTime() because the recommended JMH library is not suitable for our case. The
 * database runs in a postgres testcontainer and is extracted in the beginning.
 *
 * @author Janet Greutmann
 */
public class BenchmarkUtils {
    private static Connection connection;
    private static Map<Label, Set<Plaintext>> multimap;
    private static Vertex root;

    public static void runBenchmarkForRangeScheme(final List<EMM> emms, final int dataSize) {
        List<GenericRSScheme> rangeSchemes = new ArrayList<>();
        for (final var emm : emms) {
            try {
                rangeSchemes.add(
                        new RangeBRCScheme(
                                EMMSettings.SECURITY_PARAMETER, emm, new BestRangeCover(), root));
            } catch (GeneralSecurityException | IOException e) {
                throw new RuntimeException(e);
            }
        }
        rangeSchemes.forEach(
                el -> {
                    try {
                        runBenchmarkForSchemeAndDataSize(el, dataSize, "seq");
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    public static void runBenchmarkForParallelRangeScheme(
            final List<EMM> emms, final int dataSize) {
        List<GenericRSScheme> rangeSchemesPar = new ArrayList<>();
        for (final var emm : emms) {
            try {
                rangeSchemesPar.add(
                        new ParallelRangeBRCScheme(
                                EMMSettings.SECURITY_PARAMETER, emm, new BestRangeCover(), root));
            } catch (GeneralSecurityException | IOException e) {
                throw new RuntimeException(e);
            }
        }
        rangeSchemesPar.forEach(
                el -> {
                    try {
                        runBenchmarkForSchemeAndDataSize(el, dataSize, "par");
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    public static void runBenchmarkForDPRangeScheme(final int dataSize) {
        List<TwoRoundGenericRSScheme> dpRangeSchemes = new ArrayList<>();
        for (final var emm : EMMS.twoRoundEMMS) {
            try {
                dpRangeSchemes.add(
                        new DPRangeBRCScheme(
                                EMMSettings.SECURITY_PARAMETER, emm, new BestRangeCover(), root));
            } catch (GeneralSecurityException | IOException e) {
                throw new RuntimeException(e);
            }
        }
        dpRangeSchemes.forEach(
                el -> {
                    try {
                        runBenchmarkForSchemeAndDataSize(el, dataSize, "seq");
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    public static void runBenchmarkForParallelDPRangeScheme(final int dataSize) {
        List<TwoRoundGenericRSScheme> dpRangeSchemesPar = new ArrayList<>();
        for (final var emm : EMMS.twoRoundEMMS) {
            try {
                dpRangeSchemesPar.add(
                        new ParallelDPRangeBRCScheme(
                                EMMSettings.SECURITY_PARAMETER, emm, new BestRangeCover(), root));
            } catch (GeneralSecurityException | IOException e) {
                throw new RuntimeException(e);
            }
        }

        dpRangeSchemesPar.forEach(
                el -> {
                    try {
                        runBenchmarkForSchemeAndDataSize(el, dataSize, "par");
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    public static void initializeData() throws SQLException {
        /*
        Initializes a test container with a postgres database.
        The data set is inserted into the database.
        The first numberOfDataSamples data points are extracted from the database and build the multimap.
         */
        PostgreSQLContainer<?> postgreSQLContainer =
                new PostgreSQLContainer<>(DockerImageName.parse("postgres:latest"))
                        .withReuse(true)
                        .withInitScript("init.sql");
        System.out.println(postgreSQLContainer);
        postgreSQLContainer.start();
        String jdbcUrl = postgreSQLContainer.getJdbcUrl();
        String username = postgreSQLContainer.getUsername();
        String password = postgreSQLContainer.getPassword();
        connection = DriverManager.getConnection(jdbcUrl, username, password);
        DatabaseUtils.addData(connection);
    }

    public static void setMultimapAndRootForDataSize(final int dataSize, final int dataSet) {
        try {
            multimap = TestUtils.sampleDataFromDB(connection, dataSize, dataSet);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        root = RangeCoverUtils.getRoot(multimap);
    }

    private static EncryptedIndex runBuildIndexForSchemeAndDataSize(
            final TwoRoundGenericRSScheme scheme,
            final int dataSize,
            final String mode,
            final boolean isWarmUp)
            throws IOException {
        /*
        BUILD INDEX
         */
        final String emm = scheme.getClassOfEMM();
        System.out.println();
        System.out.println("Running build index for " + emm + " " + " with data size " + dataSize);

        ResultPrinter2 printBuildIndex = new ResultPrinter2("buildIndex");
        ResultPrinter3 printOverhead = new ResultPrinter3("overheadEncryptedIndex");

        final var startBuildIndex = System.nanoTime();
        EncryptedIndex encryptedIndex;
        try {
            encryptedIndex = scheme.buildIndex(multimap);
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
        final var endBuildIndex = System.nanoTime();
        try {
            if (!isWarmUp) {
                printBuildIndex.printToCsv(
                        emm, mode, endBuildIndex - startBuildIndex, dataSize, -1, -1);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        printOverhead.printToCsv(
                emm,
                mode,
                dataSize,
                multimap.size(),
                encryptedIndex.size(),
                scheme.getIndexDummies());
        printBuildIndex.printer.close();
        printOverhead.printer.close();
        return encryptedIndex;
    }

    private static void runTrapdoorAndSearchForSchemeDataSizeAndRangeSize(
            final TwoRoundGenericRSScheme scheme,
            final int dataSize,
            final int rangeSize,
            final EncryptedIndex encryptedIndex,
            final String mode,
            final boolean isWarmUp)
            throws IOException, GeneralSecurityException {
        final String emm = scheme.getClassOfEMM();
        /*
        TRAPDOOR
         */
        ResultPrinter2 printTrapdoor = new ResultPrinter2("trapdoor");
        final int from =
                (int) (Math.random() * (root.range().getMaximum() - rangeSize))
                        + root.range().getMinimum();
        final var range = new CustomRange(from, from + rangeSize - 1);
        final var startTrapdoor = System.nanoTime();
        final var token = scheme.trapdoor(range);
        final var endTrapdoor = System.nanoTime();
        try {
            if (!isWarmUp) {
                printTrapdoor.printToCsv(
                        emm, mode, endTrapdoor - startTrapdoor, dataSize, rangeSize, from);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        /*
        SEARCH
         */
        ResultPrinter2 printSearch = new ResultPrinter2("search");
        ResultPrinter4 printPadding = new ResultPrinter4("searchPadding");

        final var startSearch = System.nanoTime();
        final var cipherTexts = scheme.search(token, encryptedIndex);
        final var endSearch = System.nanoTime();
        try {
            if (!isWarmUp) {
                printSearch.printToCsv(
                        emm, mode, endSearch - startSearch, dataSize, rangeSize, from);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        final long dummies =
                cipherTexts.stream()
                        .map(PairLabelCiphertext.class::cast)
                        .map(PairLabelCiphertext::label)
                        .map(
                                el -> {
                                    try {
                                        return scheme.getEMM().getSeScheme().decryptLabel(el);
                                    } catch (GeneralSecurityException e) {
                                        throw new RuntimeException(e);
                                    }
                                })
                        .filter(p -> Arrays.equals(p.label(), new byte[0]))
                        .count();
        printPadding.printToCsv(emm, mode, dataSize, rangeSize, cipherTexts.size(), dummies);

        /*
        TRAPDOOR 2
         */
        ResultPrinter2 printTrapdoor2 = new ResultPrinter2("trapdoor2");
        final var startTrapdoor2 = System.nanoTime();
        final var token2 = scheme.trapdoor(range, cipherTexts);
        final var endTrapdoor2 = System.nanoTime();
        try {
            if (!isWarmUp) {
                printTrapdoor2.printToCsv(
                        emm, mode, endTrapdoor2 - startTrapdoor2, dataSize, rangeSize, from);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        /*
        SEARCH
         */
        ResultPrinter2 printSearch2 = new ResultPrinter2("search2");
        ResultPrinter4 printPadding2 = new ResultPrinter4("searchPadding2");

        final var startSearch2 = System.nanoTime();
        final var cipherTexts2 = scheme.search2(token2, encryptedIndex);
        final var endSearch2 = System.nanoTime();
        try {
            if (!isWarmUp) {
                printSearch2.printToCsv(
                        emm, mode, endSearch2 - startSearch2, dataSize, rangeSize, from);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        final long dummies2 =
                cipherTexts.stream()
                        .map(PairLabelCiphertext.class::cast)
                        .map(PairLabelCiphertext::label)
                        .map(
                                el -> {
                                    try {
                                        return scheme.getEMM().getSeScheme().decryptLabel(el);
                                    } catch (GeneralSecurityException e) {
                                        throw new RuntimeException(e);
                                    }
                                })
                        .filter(p -> Arrays.equals(p.label(), new byte[0]))
                        .count();
        printPadding2.printToCsv(emm, mode, dataSize, rangeSize, cipherTexts2.size(), dummies2);
        printTrapdoor.printer.close();
        printSearch.printer.close();
        printPadding.printer.close();
        printTrapdoor2.printer.close();
        printSearch2.printer.close();
        printPadding2.printer.close();
    }

    private static EncryptedIndex runBuildIndexForSchemeAndDataSize(
            final GenericRSScheme scheme,
            final int dataSize,
            final String mode,
            final boolean isWarmUp)
            throws IOException {
        /*
        BUILD INDEX
         */
        final String emm = scheme.getClassOfEMM();
        System.out.println();
        System.out.println("Running build index for " + emm + " " + " with data size " + dataSize);

        ResultPrinter2 printBuildIndex = new ResultPrinter2("buildIndex");
        ResultPrinter3 printOverhead = new ResultPrinter3("overheadEncryptedIndex");

        final var startBuildIndex = System.nanoTime();
        EncryptedIndex encryptedIndex;
        try {
            encryptedIndex = scheme.buildIndex(multimap);
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
        final var endBuildIndex = System.nanoTime();
        try {
            if (!isWarmUp) {
                printBuildIndex.printToCsv(
                        emm, mode, endBuildIndex - startBuildIndex, dataSize, -1, -1);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        printOverhead.printToCsv(
                emm,
                mode,
                dataSize,
                multimap.size(),
                encryptedIndex.size(),
                scheme.getIndexDummies());
        printBuildIndex.printer.close();
        printOverhead.printer.close();
        return encryptedIndex;
    }

    private static void runTrapdoorAndSearchForSchemeDataSizeAndRangeSize(
            final GenericRSScheme scheme,
            final int dataSize,
            final int rangeSize,
            final EncryptedIndex encryptedIndex,
            final String mode,
            final boolean isWarmUp)
            throws IOException {
        final String emm = scheme.getClassOfEMM();
        /*
        TRAPDOOR
         */
        ResultPrinter2 printTrapdoor = new ResultPrinter2("trapdoor");
        final int from =
                (int) (Math.random() * (root.range().getMaximum() - rangeSize))
                        + root.range().getMinimum();
        final var range = new CustomRange(from, from + rangeSize - 1);
        final var startTrapdoor = System.nanoTime();
        final var token = scheme.trapdoor(range);
        final var endTrapdoor = System.nanoTime();
        try {
            if (!isWarmUp) {
                printTrapdoor.printToCsv(
                        emm, mode, endTrapdoor - startTrapdoor, dataSize, rangeSize, from);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        /*
        SEARCH
         */
        ResultPrinter2 printSearch = new ResultPrinter2("search");
        ResultPrinter4 printPadding = new ResultPrinter4("searchPadding");

        final var startSearch = System.nanoTime();
        final var cipherTexts = scheme.search(token, encryptedIndex);
        final var endSearch = System.nanoTime();
        try {
            if (!isWarmUp) {
                printSearch.printToCsv(
                        emm, mode, endSearch - startSearch, dataSize, rangeSize, from);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        final long dummies =
                switch (emm) {
                    case "ch.bt.emm.basic.BasicEMM" -> 0;
                    default -> cipherTexts.stream()
                            .map(PairLabelCiphertext.class::cast)
                            .map(PairLabelCiphertext::label)
                            .map(
                                    el -> {
                                        try {
                                            return scheme.getEMM().getSeScheme().decryptLabel(el);
                                        } catch (GeneralSecurityException e) {
                                            throw new RuntimeException(e);
                                        }
                                    })
                            .filter(p -> Arrays.equals(p.label(), new byte[0]))
                            .count();
                };
        printPadding.printToCsv(emm, mode, dataSize, rangeSize, cipherTexts.size(), dummies);
        printTrapdoor.printer.close();
        printSearch.printer.close();
        printPadding.printer.close();
    }

    private static void runBenchmarkForSchemeAndDataSize(
            final TwoRoundGenericRSScheme scheme, final int dataSize, final String mode)
            throws IOException {
        for (int j = 0; j < BenchmarkSettings.WARM_UPS; j++) {
            runBuildIndexForSchemeAndDataSize(scheme, dataSize, mode, true);
        }
        for (int iteration = 0; iteration < BenchmarkSettings.NUMBER_OF_QUERIES; iteration++) {
            EncryptedIndex encryptedIndex;
            try {
                System.out.println(
                        "Running build index for data size "
                                + dataSize
                                + " and scheme "
                                + scheme.getEMM()
                                + " with EMM "
                                + scheme.getClassOfEMM());

                encryptedIndex = runBuildIndexForSchemeAndDataSize(scheme, dataSize, mode, false);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            final var potenitalStep = dataSize / 20;
            final var step = potenitalStep == 0 ? 1 : potenitalStep;

            for (int rangeSize = step; rangeSize <= dataSize; rangeSize += step) {
                System.out.println(
                        "Running trapdoor and search for range size "
                                + rangeSize
                                + " and data size "
                                + dataSize
                                + " and scheme "
                                + scheme.getClass()
                                + " with EMM "
                                + scheme.getClassOfEMM());

                try {
                    for (int j = 0; j < BenchmarkSettings.WARM_UPS; j++) {
                        runTrapdoorAndSearchForSchemeDataSizeAndRangeSize(
                                scheme, dataSize, rangeSize, encryptedIndex, mode, true);
                    }
                    runTrapdoorAndSearchForSchemeDataSizeAndRangeSize(
                            scheme, dataSize, rangeSize, encryptedIndex, mode, false);
                } catch (IOException | GeneralSecurityException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }

    private static void runBenchmarkForSchemeAndDataSize(
            final GenericRSScheme scheme, final int dataSize, final String mode)
            throws IOException {
        for (int iteration = 0; iteration < BenchmarkSettings.NUMBER_OF_QUERIES; iteration++) {
            EncryptedIndex encryptedIndex;
            try {
                for (int j = 0; j < BenchmarkSettings.WARM_UPS; j++) {
                    runBuildIndexForSchemeAndDataSize(scheme, dataSize, mode, true);
                }
                System.out.println("Iteration: " + iteration);
                System.out.println(
                        "Running build index for data size "
                                + dataSize
                                + " and scheme "
                                + scheme.getEMM()
                                + " with EMM "
                                + scheme.getClassOfEMM());

                encryptedIndex = runBuildIndexForSchemeAndDataSize(scheme, dataSize, mode, false);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            final var potenitalStep = dataSize / 20;
            final var step = potenitalStep == 0 ? 1 : potenitalStep;

            for (int rangeSize = step; rangeSize <= dataSize; rangeSize += step) {
                System.out.println(
                        "Running trapdoor and search for range size "
                                + rangeSize
                                + " and data size "
                                + dataSize
                                + " and scheme "
                                + scheme.getClass()
                                + " with EMM "
                                + scheme.getClassOfEMM());

                try {
                    for (int j = 0; j < BenchmarkSettings.WARM_UPS; j++) {
                        runTrapdoorAndSearchForSchemeDataSizeAndRangeSize(
                                scheme, dataSize, rangeSize, encryptedIndex, mode, true);
                    }
                    runTrapdoorAndSearchForSchemeDataSizeAndRangeSize(
                            scheme, dataSize, rangeSize, encryptedIndex, mode, false);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }
}
