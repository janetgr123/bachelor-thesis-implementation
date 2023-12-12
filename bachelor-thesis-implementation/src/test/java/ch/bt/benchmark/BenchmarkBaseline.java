package ch.bt.benchmark;

import ch.bt.TestUtils;
import ch.bt.emm.basic.BasicEMM;
import ch.bt.genericRs.RangeBRCScheme;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.bt.rc.BestRangeCover;
import ch.bt.rc.RangeCoverUtils;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.openjdk.jmh.annotations.*;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Map;
import java.util.Set;

@State(Scope.Benchmark)
public class BenchmarkBaseline {

    int securityParameter = 256;
    Map<Label, Set<Plaintext>> multimap;

    Vertex root;

    CustomRange range;
    RangeBRCScheme rangeBRCScheme;

    @Setup
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
        range = new CustomRange(27, 55);
        final var basicEMM = new BasicEMM(securityParameter);
        rangeBRCScheme =
                new RangeBRCScheme(securityParameter, basicEMM, new BestRangeCover(), root);
    }

    @Benchmark
    public void baselineBuildIndex() throws GeneralSecurityException, IOException {
        rangeBRCScheme.buildIndex(multimap);
    }
}
