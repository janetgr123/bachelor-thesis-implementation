package ch.bt.benchmark.baseline.sequential;

import ch.bt.TestUtils;
import ch.bt.benchmark.BenchmarkUtils;
import ch.bt.emm.basic.BasicEMM;
import ch.bt.genericRs.RangeBRCScheme;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.bt.model.searchtoken.SearchToken;
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
import java.util.List;
import java.util.Map;
import java.util.Set;

public class BaselineTrapdoor {

    @State(Scope.Benchmark)
    public static class Constants {
        final String folder = "src/test/resources/benchmark/baseline/sequential";

        final String method = "trapdoor";
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
                final String col4,
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
            fileWriter =
                    Files.newBufferedWriter(
                            Paths.get(String.join("/", constants.folder, file)),
                            StandardOpenOption.APPEND,
                            StandardOpenOption.CREATE);
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
        @Param("0")
        int numberOfDataSamples;

        @Param("0")
        int from;

        @Param("0")
        int to;

        Map<Label, Set<Plaintext>> multimap;
        RangeBRCScheme rangeBRCScheme;
        Vertex root;
        EncryptedIndex encryptedIndex;
        CustomRange range;

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
            root = RangeCoverUtils.getRoot(multimap);
            range = new CustomRange(from, to);

            final int securityParameter = 256;
            final var emm = new BasicEMM(securityParameter);
            rangeBRCScheme = new RangeBRCScheme(securityParameter, emm, new BestRangeCover(), root);
            encryptedIndex = rangeBRCScheme.buildIndex(multimap);
        }
    }

    @Benchmark
    public List<SearchToken> trapdoor(@NotNull Parameters parameters) {
        return parameters.rangeBRCScheme.trapdoor(parameters.range);
    }
}
