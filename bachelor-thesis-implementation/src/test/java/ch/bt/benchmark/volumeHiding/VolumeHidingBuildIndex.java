package ch.bt.benchmark.volumeHiding;

import ch.bt.TestUtils;
import ch.bt.benchmark.BenchmarkUtils;
import ch.bt.emm.volumeHiding.VolumeHidingEMM;
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

public class VolumeHidingBuildIndex {
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

        @Setup(Level.Invocation)
        public void init() throws GeneralSecurityException, IOException, SQLException {
            fileWriter =
                    new FileWriter("src/test/resources/benchmark/volumeHiding/index-sizes.csv");
            csvFormat = CSVFormat.DEFAULT.builder().setHeader("map", "size").build();
            printer = new CSVPrinter(fileWriter, csvFormat);
        }
    }

    @State(Scope.Benchmark)
    public static class Parameters {
        Map<Label, Set<Plaintext>> multimap;
        RangeBRCScheme rangeBRCScheme;
        EncryptedIndex encryptedIndex;

        @Setup(Level.Invocation)
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

            final var emm = new VolumeHidingEMM(securityParameter, TestUtils.ALPHA);
            rangeBRCScheme = new RangeBRCScheme(securityParameter, emm, new BestRangeCover(), root);
        }

        @TearDown(Level.Invocation)
        public void tearDown(@NotNull IndexSizePrinter printer)
                throws IOException, SQLException, GeneralSecurityException {
            printer.printToCsv("multimap", multimap.size());
            printer.printToCsv("encrypted index baseline", encryptedIndex.size());
            printer.printer.close();
        }
    }

    @Benchmark
    public EncryptedIndex buildIndex(@NotNull Parameters parameters)
            throws GeneralSecurityException, IOException {
        parameters.encryptedIndex = parameters.rangeBRCScheme.buildIndex(parameters.multimap);
        return parameters.encryptedIndex;
    }
}
