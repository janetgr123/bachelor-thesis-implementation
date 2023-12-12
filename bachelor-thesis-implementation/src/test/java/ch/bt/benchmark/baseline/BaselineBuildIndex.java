package ch.bt.benchmark.baseline;

import ch.bt.TestUtils;
import ch.bt.benchmark.BenchmarkUtils;
import ch.bt.emm.basic.BasicEMM;
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

public class BaselineBuildIndex {

    @State(Scope.Benchmark)
    public static class IndexSizePrinter {
        FileWriter fileWriter;
        CSVFormat csvFormat;
        CSVPrinter printer;

        public void printToCsv(final String map, final int size)
                throws IOException, SQLException, GeneralSecurityException {
            if (printer == null) {
                init();
            }
            printer.printRecord(map, size);
        }

        @Setup(Level.Trial)
        public void init() throws GeneralSecurityException, IOException, SQLException {
            fileWriter = new FileWriter("src/test/resources/benchmark/baseline/index-sizes.csv");
            csvFormat = CSVFormat.DEFAULT.builder().setHeader("map", "size").build();
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

            final var basicEMM = new BasicEMM(securityParameter);
            rangeBRCScheme =
                    new RangeBRCScheme(securityParameter, basicEMM, new BestRangeCover(), root);
        }

        @TearDown(Level.Trial)
        public void tearDown(@NotNull IndexSizePrinter printer)
                throws IOException, SQLException, GeneralSecurityException {
            printer.printToCsv("multimap", multimap.size());
            printer.printToCsv("encrypted index baseline", encryptedIndex.size());
        }
    }

    @Benchmark
    public EncryptedIndex buildIndex(@NotNull Parameters parameters)
            throws GeneralSecurityException, IOException {
        parameters.encryptedIndex = parameters.rangeBRCScheme.buildIndex(parameters.multimap);
        return parameters.encryptedIndex;
    }
}
