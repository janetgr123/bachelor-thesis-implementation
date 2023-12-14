package ch.bt.benchmark.dpVolumeHiding.sequential;

import ch.bt.TestUtils;
import ch.bt.benchmark.BenchmarkUtils;
import ch.bt.emm.TwoRoundEMM;
import ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM;
import ch.bt.genericRs.DPRangeBRCScheme;
import ch.bt.model.encryptedindex.EncryptedIndex;
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
import java.util.Map;
import java.util.Set;

public class DpVolumeHidingBuildIndex {

    @State(Scope.Benchmark)
    public static class Constants {
        final String folder = "src/test/resources/benchmark/dpVolumeHiding/sequential/data";

        final String method = "build-index";
    }

    @State(Scope.Benchmark)
    public static class ResultPrinter {
        BufferedWriter fileWriter;
        CSVFormat csvFormat;
        CSVPrinter printer;

        public void printToCsv(
                final int col1,
                final int col2,
                final int col3,
                final int col4,
                @NotNull Constants constants)
                throws IOException, SQLException, GeneralSecurityException {
            if (printer == null) {
                init(constants);
            }
            printer.printRecord(col1, col2, col3, col4);
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
    public static class Parameters {
        @Param("0")
        int numberOfDataSamples;

        Map<Label, Set<Plaintext>> multimap;
        DPRangeBRCScheme rangeBRCScheme;
        EncryptedIndex encryptedIndex;
        TwoRoundEMM emm;

        @Setup(Level.Trial)
        public void init() throws GeneralSecurityException, IOException, SQLException {
            Security.addProvider(new BouncyCastleFipsProvider());

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

            multimap = TestUtils.getDataFromDB(connection, numberOfDataSamples);
            final Vertex root = RangeCoverUtils.getRoot(multimap);

            final int securityParameter = 256;

            emm = new DifferentiallyPrivateVolumeHidingEMM(securityParameter, 0.2, TestUtils.ALPHA);
            rangeBRCScheme =
                    new DPRangeBRCScheme(securityParameter, emm, new BestRangeCover(), root);
            encryptedIndex = rangeBRCScheme.buildIndex(multimap);
        }

        @TearDown(Level.Trial)
        public void tearDown(@NotNull ResultPrinter printer, @NotNull Constants constants)
                throws IOException, SQLException, GeneralSecurityException {
            printer.printToCsv(
                    numberOfDataSamples,
                    multimap.size(),
                    encryptedIndex.size(),
                    emm.getNumberOfDummyValues(),
                    constants);
        }
    }

    @Benchmark
    public EncryptedIndex buildIndex(@NotNull Parameters parameters)
            throws GeneralSecurityException, IOException {
        parameters.encryptedIndex = parameters.rangeBRCScheme.buildIndex(parameters.multimap);
        return parameters.encryptedIndex;
    }
}
