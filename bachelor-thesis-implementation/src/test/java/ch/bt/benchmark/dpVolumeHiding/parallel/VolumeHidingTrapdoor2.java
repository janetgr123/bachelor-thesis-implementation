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

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.jetbrains.annotations.NotNull;
import org.openjdk.jmh.annotations.*;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class VolumeHidingTrapdoor2 {

    @State(Scope.Benchmark)
    public static class Parameters {
        @Param("0")
        int numberOfDataSamples;

        @Param("0")
        int from;

        @Param("0")
        int to;

        Map<Label, Set<Plaintext>> multimap;
        ParallelDPRangeBRCScheme rangeBRCScheme;
        Vertex root;
        EncryptedIndex encryptedIndex;
        CustomRange range;

        Set<Ciphertext> ciphertexts;

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
            final var emm =
                    new DifferentiallyPrivateVolumeHidingEMM(
                            securityParameter, 0.2, TestUtils.ALPHA);
            rangeBRCScheme =
                    new ParallelDPRangeBRCScheme(
                            securityParameter, emm, new BestRangeCover(), root);
            encryptedIndex = rangeBRCScheme.buildIndex(multimap);
            final var searchToken = rangeBRCScheme.trapdoor(range);
            ciphertexts = rangeBRCScheme.search(searchToken, encryptedIndex);
        }
    }

    @Benchmark
    public List<SearchToken> trapdoor(@NotNull Parameters parameters)
            throws GeneralSecurityException, IOException {
        return parameters.rangeBRCScheme.trapdoor(parameters.range, parameters.ciphertexts);
    }
}
