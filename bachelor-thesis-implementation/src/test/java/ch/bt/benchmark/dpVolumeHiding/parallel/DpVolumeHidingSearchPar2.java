package ch.bt.benchmark.dpVolumeHiding.parallel;

import ch.bt.TestUtils;
import ch.bt.benchmark.BenchmarkUtils;
import ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM;
import ch.bt.genericRs.ParallelDPRangeBRCScheme;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.multimap.Ciphertext;
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

public class DpVolumeHidingSearchPar2 {

    @State(Scope.Benchmark)
    public static class Constants {
        final String folder = "src/test/resources/benchmark/dpVolumeHiding/parallel";
        final String method = "search2";
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
                final String col6,
                final int col7,
                final String col8,
                final int col9,
                final String col10,
                final int col11,
                @NotNull Constants constants)
                throws IOException, SQLException, GeneralSecurityException {
            if (printer == null) {
                init(constants);
            }
            printer.printRecord(col1, col2, col3, col4, col5, col6, col7, col8, col9, col10, col11);
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
        Map<Label, Set<Plaintext>> multimap;
        ParallelDPRangeBRCScheme rangeBRCScheme;
        Vertex root;
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
            root = RangeCoverUtils.getRoot(multimap);

            final int securityParameter = 256;

            final var emm =
                    new DifferentiallyPrivateVolumeHidingEMM(
                            securityParameter, 0.2, TestUtils.ALPHA);
            rangeBRCScheme =
                    new ParallelDPRangeBRCScheme(
                            securityParameter, emm, new BestRangeCover(), root);
            encryptedIndex = rangeBRCScheme.buildIndex(multimap);
        }
    }

    @State(Scope.Thread)
    public static class RangeSchemeState {
        Set<Ciphertext> ciphertexts;
        List<SearchToken> searchToken;
        List<SearchToken> searchToken2;
        CustomRange range;

        @Setup(Level.Trial)
        public void sampleRange(
                @NotNull ResultPrinter printer,
                @NotNull Constants constants,
                @NotNull Parameters parameters)
                throws IOException, SQLException, GeneralSecurityException {
            final var rootRange = parameters.root.range();
            final int max = rootRange.getMaximum();
            int size = (int) (Math.random() * rootRange.size());
            int from = (int) (Math.random() * max) + rootRange.getMinimum();
            range = new CustomRange(from, Math.min(from + size - 1, max));
            searchToken = parameters.rangeBRCScheme.trapdoor(range);
            ciphertexts = parameters.rangeBRCScheme.search(searchToken, parameters.encryptedIndex);
            searchToken2 = parameters.rangeBRCScheme.trapdoor(range, ciphertexts);
            final var ciphertexts2 =
                    parameters.rangeBRCScheme.search2(searchToken2, parameters.encryptedIndex);
            printer.printToCsv(
                    "range",
                    range.getMinimum(),
                    range.getMaximum(),
                    "token",
                    searchToken.size(),
                    "ciphertexts",
                    ciphertexts.size(),
                    "token2",
                    searchToken2.size(),
                    "ciphertexts2",
                    ciphertexts2.size(),
                    constants);
        }
    }

    @Benchmark
    public Set<Ciphertext> search2(
            @NotNull Parameters rangeSchemeParameters, @NotNull RangeSchemeState state) {
        return rangeSchemeParameters.rangeBRCScheme.search2(
                state.searchToken2, rangeSchemeParameters.encryptedIndex);
    }
}
