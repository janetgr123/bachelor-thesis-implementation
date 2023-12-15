package ch.bt.benchmark;

import ch.bt.TestUtils;
import ch.bt.emm.EMM;
import ch.bt.emm.basic.BasicEMM;
import ch.bt.emm.volumeHiding.VolumeHidingEMM;
import ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised;
import ch.bt.genericRs.RangeBRCScheme;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexMap;
import ch.bt.model.encryptedindex.EncryptedIndexTables;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.rc.Vertex;
import ch.bt.rc.BestRangeCover;
import ch.bt.rc.RangeCoverUtils;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.jetbrains.annotations.NotNull;
import org.openjdk.jmh.annotations.*;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.*;

public class BuildIndex {

    @State(Scope.Benchmark)
    public static class Constants {
        final String folder = "src/test/resources/benchmark";

        final String method = "build-index";
    }

    @State(Scope.Benchmark)
    public static class ResultPrinter {
        BufferedWriter fileWriter;
        CSVFormat csvFormat;
        CSVPrinter printer;

        public void printToCsv(
                final String col1,
                final int col2,
                final int col3,
                final int col4,
                final int col5,
                @NotNull Constants constants)
                throws IOException, SQLException, GeneralSecurityException {
            if (printer == null) {
                init(constants);
            }
            printer.printRecord(col1, col2, col3, col4, col5);
        }

        @Setup(Level.Trial)
        public void init(@NotNull Constants constants)
                throws GeneralSecurityException, IOException, SQLException {
            final String file =
                    String.join(".", String.join("-", "results", constants.method), "csv");
            final var path = Paths.get(String.join("/", constants.folder, file));
            final var newFile = path.toFile();
            if (newFile.exists()) {
                csvFormat = CSVFormat.DEFAULT.builder().build();
            } else {
                csvFormat =
                        CSVFormat.DEFAULT
                                .builder()
                                .setHeader(
                                        "type",
                                        "data size",
                                        "multimap size",
                                        "encrypted index size",
                                        "dummy entries in encrypted index")
                                .build();
            }
            fileWriter =
                    Files.newBufferedWriter(
                            path, StandardOpenOption.APPEND, StandardOpenOption.CREATE);
            printer = new CSVPrinter(fileWriter, csvFormat);
        }

        @TearDown(Level.Trial)
        public void tearDown() throws IOException {
            printer.close();
        }
    }

    @State(Scope.Benchmark)
    public static class RootPrinter {
        BufferedWriter fileWriter;
        CSVFormat csvFormat;
        CSVPrinter printer;

        public void printToCsv(
                final String type,
                final int dataSize,
                final String rootId,
                final int rootFrom,
                final int rootTo,
                @NotNull Constants constants)
                throws IOException, SQLException, GeneralSecurityException {
            if (printer == null) {
                init(constants);
            }
            printer.printRecord(type, dataSize, rootId, rootFrom, rootTo);
        }

        @Setup(Level.Trial)
        public void init(@NotNull Constants constants)
                throws GeneralSecurityException, IOException, SQLException {
            final String file = String.join(".", String.join("-", "root", constants.method), "csv");
            final var path = Paths.get(String.join("/", constants.folder, file));
            final var newFile = path.toFile();
            if (newFile.exists()) {
                csvFormat = CSVFormat.DEFAULT.builder().build();
            } else {
                csvFormat =
                        CSVFormat.DEFAULT
                                .builder()
                                .setHeader("type", "data size", "root id", "root from", "root to")
                                .build();
            }
            fileWriter =
                    Files.newBufferedWriter(
                            path, StandardOpenOption.APPEND, StandardOpenOption.CREATE);
            printer = new CSVPrinter(fileWriter, csvFormat);
        }

        @TearDown(Level.Trial)
        public void tearDown() throws IOException {
            printer.close();
        }
    }

    @State(Scope.Benchmark)
    public static class EncryptedIndexPrinter {
        BufferedWriter fileWriter;
        CSVFormat csvFormat;
        CSVPrinter printer;

        public void printToCsv(
                final String type,
                final int tableNumber,
                final int dataSize,
                final byte[] labelData,
                final byte[] labelIv,
                final byte[] value1Data,
                final byte[] value1Iv,
                @NotNull Constants constants)
                throws IOException, SQLException, GeneralSecurityException {
            if (printer == null) {
                init(constants);
            }
            printer.printRecord(
                    type,
                    tableNumber,
                    dataSize,
                    Arrays.toString(labelData),
                    Arrays.toString(labelIv),
                    Arrays.toString(value1Data),
                    Arrays.toString(value1Iv));
        }

        @Setup(Level.Trial)
        public void init(@NotNull Constants constants)
                throws GeneralSecurityException, IOException, SQLException {
            final String file =
                    String.join(".", String.join("-", "encryptedIndex", constants.method), "csv");
            final var path = Paths.get(String.join("/", constants.folder, file));
            final var newFile = path.toFile();
            if (newFile.exists()) {
                csvFormat =
                        CSVFormat.DEFAULT
                                .builder()
                                .setHeader(
                                        "type",
                                        "table number",
                                        "data size",
                                        "label data",
                                        "label iv",
                                        "value1 data",
                                        "value1 iv")
                                .build();
            } else {
                csvFormat = CSVFormat.DEFAULT.builder().build();
            }
            fileWriter =
                    Files.newBufferedWriter(
                            path, StandardOpenOption.APPEND, StandardOpenOption.CREATE);
            printer = new CSVPrinter(fileWriter, csvFormat);
        }

        @TearDown(Level.Trial)
        public void tearDown() throws IOException {
            printer.close();
        }
    }

    @State(Scope.Benchmark)
    public static class Multimap {
        Map<String, Boolean> printed = new HashMap<>();
        int securityParameter = 256;

        @Param("0")
        int numberOfDataSamples;

        Map<Label, Set<Plaintext>> multimap;

        Vertex root;
        boolean rootPrinted = false;

        // NOTE: runs only once per benchmark of this type
        @Setup(Level.Trial)
        public void init() throws GeneralSecurityException, IOException, SQLException {
            System.out.println();
            System.out.println("INITIALIZE BENCHMARK: SETUP DB CONTAINER AND MULTIMAP");
            System.out.println("------------------------------------------------------");

            Security.addProvider(new BouncyCastleFipsProvider());

            /*
            Initializes a test container with a postgres database.
            The data set is inserted into the database.
            The first $numberOfDataSamples data points are extracted from the database and build the multimap.
             */
            PostgreSQLContainer<?> postgreSQLContainer =
                    new PostgreSQLContainer<>(DockerImageName.parse("postgres:latest"))
                            .withReuse(true)
                            .withInitScript("init.sql");
            postgreSQLContainer.start();
            String jdbcUrl = postgreSQLContainer.getJdbcUrl();
            String username = postgreSQLContainer.getUsername();
            String password = postgreSQLContainer.getPassword();
            Connection connection = DriverManager.getConnection(jdbcUrl, username, password);
            DatabaseUtils.addData(connection);

            multimap = TestUtils.getDataFromDB(connection, numberOfDataSamples);
            root = RangeCoverUtils.getRoot(multimap);

            printed.put("baseline", false);
            printed.put("volumeHiding", false);
            printed.put("volumeHidingOpt", false);
        }
    }

    @State(Scope.Benchmark)
    public static class Parameters {
        @Param("baseline")
        String type;

        RangeBRCScheme rangeBRCScheme;
        EncryptedIndex encryptedIndex;
        EMM emm;

        @Setup(Level.Iteration)
        public void init(
                @NotNull Multimap multimap,
                @NotNull RootPrinter printer,
                @NotNull Constants constants)
                throws GeneralSecurityException, IOException, SQLException {
            emm =
                    switch (type) {
                        case "volumeHiding" -> new VolumeHidingEMM(
                                multimap.securityParameter, TestUtils.ALPHA);
                        case "volumeHidingOpt" -> new VolumeHidingEMMOptimised(
                                multimap.securityParameter, TestUtils.ALPHA);
                        default -> new BasicEMM(multimap.securityParameter);
                    };

            System.out.println();
            System.out.println(
                    "Iteration with Dataset Size "
                            + multimap.numberOfDataSamples
                            + " and Range Scheme Type "
                            + emm.getClass());

            rangeBRCScheme =
                    new RangeBRCScheme(
                            multimap.securityParameter, emm, new BestRangeCover(), multimap.root);

            if (!multimap.rootPrinted) {
                multimap.rootPrinted = true;
                System.out.println();
                System.out.println("Save root to file...");
                final var rootRange = multimap.root.range();
                printer.printToCsv(
                        type,
                        multimap.numberOfDataSamples,
                        multimap.root.id(),
                        rootRange.getMinimum(),
                        rootRange.getMaximum(),
                        constants);
            }
        }

        // NOTE: this is running every iteration of the benchmark
        @TearDown(Level.Iteration)
        public void tearDown(
                @NotNull ResultPrinter printer,
                @NotNull EncryptedIndexPrinter encryptedIndexPrinter,
                @NotNull Constants constants,
                @NotNull Multimap multimap)
                throws IOException, SQLException, GeneralSecurityException {
            System.out.println("End of Iteration...");

            if (!multimap.printed.containsKey(type) || !multimap.printed.get(type)) {
                printer.printToCsv(
                        type,
                        multimap.numberOfDataSamples,
                        multimap.multimap.size(),
                        encryptedIndex.size(),
                        emm.getNumberOfDummyValues(),
                        constants);
                multimap.printed.put(type, true);

                System.out.println("Save encrypted index to csv...");
                final var index =
                        switch (type) {
                            case "volumeHiding", "volumeHidingOpt" -> (EncryptedIndexTables)
                                    encryptedIndex;
                            default -> (EncryptedIndexMap) encryptedIndex;
                        };
                if (index instanceof EncryptedIndexMap) {
                    final var map = ((EncryptedIndexMap) index).map();
                    final var keys = map.keySet();
                    keys.forEach(
                            key -> {
                                try {
                                    encryptedIndexPrinter.printToCsv(
                                            type,
                                            -1,
                                            multimap.numberOfDataSamples,
                                            key.label(),
                                            null,
                                            map.get(key).data(),
                                            map.get(key).iv(),
                                            constants);
                                } catch (IOException | SQLException | GeneralSecurityException e) {
                                    throw new RuntimeException(e);
                                }
                            });
                } else if (index instanceof EncryptedIndexTables) {
                    for (int i = 0; i < 2; i++) {
                        final var table = ((EncryptedIndexTables) index).getTable(i);
                        for (final var entry : table) {
                            final var label = entry.label();
                            final var value = entry.value();
                            encryptedIndexPrinter.printToCsv(
                                    "volumeHiding",
                                    i,
                                    multimap.numberOfDataSamples,
                                    label.data(),
                                    label.iv(),
                                    value.data(),
                                    value.iv(),
                                    constants);
                        }
                    }
                } else {
                    // TODO
                }
            }
        }
    }

    @Benchmark
    public EncryptedIndex buildIndex(@NotNull Parameters parameters, @NotNull Multimap multimap)
            throws GeneralSecurityException, IOException {
        parameters.encryptedIndex = parameters.rangeBRCScheme.buildIndex(multimap.multimap);
        return parameters.encryptedIndex;
    }
}
