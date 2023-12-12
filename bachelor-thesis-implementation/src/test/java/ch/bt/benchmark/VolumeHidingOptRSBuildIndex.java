package ch.bt.benchmark;

import ch.bt.TestUtils;
import ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised;
import ch.bt.genericRs.RangeBRCScheme;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.rc.CustomRange;
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

public class VolumeHidingOptRSBuildIndex {

    @State(Scope.Benchmark)
    public static class IndexSizePrinter {
        FileWriter fileWriter;
        CSVFormat csvFormat;
        CSVPrinter printer;

        public void printToCsv(final String map, final int size) throws IOException {
            printer.printRecord(map, size);
        }

        @Setup(Level.Invocation)
        public void init() throws GeneralSecurityException, IOException, SQLException {
            fileWriter = new FileWriter("src/test/resources/index_sizes_vh_opt.csv");
            csvFormat = CSVFormat.DEFAULT.builder().setHeader("Map", "size").build();
            printer = new CSVPrinter(fileWriter, csvFormat);
        }
    }

    @State(Scope.Benchmark)
    public static class Parameters {
        Map<Label, Set<Plaintext>> multimap;
        RangeBRCScheme rangeBRCScheme;
        EncryptedIndex encryptedIndex;

        @Setup(Level.Invocation)
        public void init(@NotNull IndexSizePrinter printer)
                throws GeneralSecurityException, IOException, SQLException {
            final int securityParameter = 256;

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
            final var emm = new VolumeHidingEMMOptimised(securityParameter, TestUtils.ALPHA);
            rangeBRCScheme = new RangeBRCScheme(securityParameter, emm, new BestRangeCover(), root);
            printer.printToCsv("multimap", multimap.size());
        }

        @TearDown(Level.Iteration)
        public void tearDown(@NotNull IndexSizePrinter printer) throws IOException {
            printer.printToCsv("encrypted index", encryptedIndex.size());
            printer.printer.close();
        }
    }

    @State(Scope.Thread)
    public static class RangeSchemeState {
        CustomRange range;

        @Setup(Level.Iteration)
        public void sampleRange() {
            int size = (int) (Math.random() + 1) * 10;
            int from = (int) (Math.random() + 1) * 100;
            range = new CustomRange(from, from + size - 1);
        }
    }

    @Benchmark
    public EncryptedIndex buildIndex(@NotNull Parameters parameters)
            throws GeneralSecurityException, IOException {
        parameters.encryptedIndex = parameters.rangeBRCScheme.buildIndex(parameters.multimap);
        return parameters.encryptedIndex;
    }
}
