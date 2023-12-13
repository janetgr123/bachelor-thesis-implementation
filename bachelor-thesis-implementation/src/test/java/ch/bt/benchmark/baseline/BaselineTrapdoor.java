package ch.bt.benchmark.baseline;

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

import java.io.FileWriter;
import java.io.IOException;
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
        final String folder = "src/test/resources/benchmark/baseline";
        final String category = "baseline";

        final String method = "trapdoor";
    }

    @State(Scope.Benchmark)
    public static class ResultPrinter {
        FileWriter fileWriter;
        CSVFormat csvFormat;
        CSVPrinter printer;

        public void printToCsv(
                final String col1, final int col2, final int col3, @NotNull Constants constants)
                throws IOException, SQLException, GeneralSecurityException {
            if (printer == null) {
                init(constants);
            }
            printer.printRecord(col1, col2, col3);
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

            final var emm = new BasicEMM(securityParameter);
            rangeBRCScheme = new RangeBRCScheme(securityParameter, emm, new BestRangeCover(), root);
            encryptedIndex = rangeBRCScheme.buildIndex(multimap);
        }

        @TearDown(Level.Trial)
        public void tearDown(@NotNull ResultPrinter printer, @NotNull Constants constants)
                throws IOException, SQLException, GeneralSecurityException {
            printer.printToCsv("multimap", multimap.size(), -1, constants);
            printer.printToCsv(
                    String.join(" ", "encrypted index", constants.category),
                    encryptedIndex.size(),
                    -1,
                    constants);
        }
    }

    @State(Scope.Thread)
    public static class RangeSchemeState {
        CustomRange range;
        List<SearchToken> searchToken;

        @Setup(Level.Iteration)
        public void sampleRange(
                @NotNull ResultPrinter printer,
                @NotNull Constants constants,
                @NotNull Parameters parameters)
                throws IOException, SQLException, GeneralSecurityException {
            final int max = TestUtils.TEST_DATA_SET_SIZE;
            int size = (int) (Math.random() * max) + 1;
            int from = (int) (Math.random() * max) + 1;
            range = new CustomRange(from, Math.min(from + size - 1, max));
            searchToken = parameters.rangeBRCScheme.trapdoor(range);
            printer.printToCsv("range", range.getMinimum(), range.getMaximum(), constants);
            printer.printToCsv("token", searchToken.size(), -1, constants);
        }
    }

    @Benchmark
    public List<SearchToken> trapdoor(
            @NotNull Parameters rangeSchemeParameters, @NotNull RangeSchemeState state) {
        return rangeSchemeParameters.rangeBRCScheme.trapdoor(state.range);
    }
}
