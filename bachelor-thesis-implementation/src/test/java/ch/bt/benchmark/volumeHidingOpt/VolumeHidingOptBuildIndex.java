package ch.bt.benchmark.volumeHidingOpt;

import ch.bt.TestUtils;
import ch.bt.benchmark.BenchmarkUtils;
import ch.bt.emm.EMM;
import ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised;
import ch.bt.genericRs.RangeBRCScheme;
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

import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Map;
import java.util.Set;

public class VolumeHidingOptBuildIndex {

    @State(Scope.Benchmark)
    public static class Constants {
        final String folder = "src/test/resources/benchmark/volumeHidingOpt";
        final String method = "build-index";
    }

    @State(Scope.Benchmark)
    public static class ResultPrinter {
        FileWriter fileWriter;
        CSVFormat csvFormat;
        CSVPrinter printer;

        public void printToCsv(final String col1, final int col2, @NotNull Constants constants)
                throws IOException, SQLException, GeneralSecurityException {
            if (printer == null) {
                init(constants);
            }
            printer.printRecord(col1, col2);
        }

        @Setup(Level.Trial)
        public void init(@NotNull Constants constants)
                throws GeneralSecurityException, IOException, SQLException {
            final String file =
                    String.join(".", String.join("-", "results", constants.method), "csv");
            fileWriter = new FileWriter(String.join("/", constants.folder, file));
            csvFormat = CSVFormat.DEFAULT.builder().build();
            printer = new CSVPrinter(fileWriter, csvFormat);
        }

        @TearDown(Level.Trial)
        public void tearDown() throws IOException {
            printer.close();
        }
    }

    @State(Scope.Benchmark)
    public static class Parameters {
        Map<Label, Set<Plaintext>> multimap;
        RangeBRCScheme rangeBRCScheme;
        EncryptedIndex encryptedIndex;

        EMM emm;

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

            multimap = TestUtils.getDataFromDB(connection);
            final Vertex root = RangeCoverUtils.getRoot(multimap);

            final int securityParameter = 256;

            emm = new VolumeHidingEMMOptimised(securityParameter, TestUtils.ALPHA);
            rangeBRCScheme = new RangeBRCScheme(securityParameter, emm, new BestRangeCover(), root);
            encryptedIndex = rangeBRCScheme.buildIndex(multimap);
        }

        @TearDown(Level.Trial)
        public void tearDown(@NotNull ResultPrinter printer, @NotNull Constants constants)
                throws IOException, SQLException, GeneralSecurityException {
            printer.printToCsv("multimap", multimap.size(), constants);
            printer.printToCsv("encrypted index", encryptedIndex.size(), constants);
            printer.printToCsv("dummy values", emm.getNumberOfDummyValues(), constants);
        }
    }

    @Benchmark
    public EncryptedIndex buildIndex(@NotNull Parameters parameters)
            throws GeneralSecurityException, IOException {
        parameters.encryptedIndex = parameters.rangeBRCScheme.buildIndex(parameters.multimap);
        return parameters.encryptedIndex;
    }
}
