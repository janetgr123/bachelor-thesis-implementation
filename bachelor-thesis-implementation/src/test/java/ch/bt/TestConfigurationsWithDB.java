package ch.bt;

import ch.bt.model.db.NetworkEdge;
import ch.bt.model.db.NetworkNode;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.io.*;
import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * <a
 * href="https://stackoverflow.com/questions/43282798/in-junit-5-how-to-run-code-before-all-tests">...</a>
 * date accessed: 22.11.2023
 *
 * <p><a href="https://www.baeldung.com/docker-test-containers">...</a> date accessed: 22.11.2023
 *
 * <p><a
 * href="https://learn.microsoft.com/en-us/sql/connect/jdbc/performing-batch-operations?view=sql-server-ver16&redirectedfrom=MSDN">...</a>
 * date accessed: 22.11.2023
 */
public class TestConfigurationsWithDB implements BeforeAllCallback {
    private static boolean started = false;
    public static Connection connection;

    @Override
    public void beforeAll(ExtensionContext extensionContext) throws SQLException {
        if (!started) {
            started = true;
            Security.addProvider(new BouncyCastleFipsProvider());

            PostgreSQLContainer<?> postgreSQLContainer =
                    new PostgreSQLContainer<>(DockerImageName.parse("postgres:latest"))
                            .withReuse(true)
                            .withInitScript("init.sql");
            postgreSQLContainer.start();
            String jdbcUrl = postgreSQLContainer.getJdbcUrl();
            String username = postgreSQLContainer.getUsername();
            String password = postgreSQLContainer.getPassword();
            connection = DriverManager.getConnection(jdbcUrl, username, password);
            addData();
            addData2();
            TestUtils.init();
            extensionContext
                    .getRoot()
                    .getStore(ExtensionContext.Namespace.GLOBAL)
                    .put("test configurations with db", this);
        }
    }

    private void addData() {
        try (final var input = getClass().getResourceAsStream("/data/data.csv")) {
            CSVParser parser = new CSVParser(new InputStreamReader(input), CSVFormat.DEFAULT);
            final var records =
                    parser.stream()
                            .map(
                                    el -> {
                                        final var string = el.get(0);
                                        final var split = string.split(" ");
                                        return new NetworkNode(
                                                Integer.parseInt(split[0]),
                                                Double.parseDouble(split[1]),
                                                Double.parseDouble(split[2]));
                                    })
                            .toList();

            int counter = 0;
            Statement stmt = null;
            for (final var node : records) {
                if (counter % 10 == 0) {
                    if (stmt != null) {
                        int[] updateCounts = stmt.executeBatch();
                        stmt.close();
                    }
                    try {
                        stmt = connection.createStatement();
                    } catch (SQLException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    stmt.addBatch(
                            "insert into test.public.t_network_nodes (pk_node_id, latitude, longitude) VALUES ("
                                    + node.id()
                                    + ", "
                                    + node.latitude()
                                    + ", "
                                    + node.longitude()
                                    + ")");
                }
                counter++;
            }
        } catch (IOException | SQLException e) {
            throw new RuntimeException(e);
        }
    }

    private void addData2() {
        try (final var input = getClass().getResourceAsStream("/data/data2.csv")) {
            CSVParser parser = new CSVParser(new InputStreamReader(input), CSVFormat.DEFAULT);
            final var records =
                    parser.stream()
                            .map(
                                    el -> {
                                        final var string = el.get(0);
                                        final var split = string.split(" ");
                                        return new NetworkEdge(
                                                Integer.parseInt(split[0]),
                                                Integer.parseInt(split[1]),
                                                Integer.parseInt(split[2]),
                                                Double.parseDouble(split[3]));
                                    })
                            .toList();

            int counter = 0;
            Statement stmt = null;
            for (final var node : records) {
                if (counter % 10 == 0) {
                    if (stmt != null) {
                        int[] updateCounts = stmt.executeBatch();
                        stmt.close();
                    }
                    try {
                        stmt = connection.createStatement();
                    } catch (SQLException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    stmt.addBatch(
                            "insert into test.public.t_network_edges (pk_edge_id, start_node, end_node, distance) VALUES ("
                                    + node.id()
                                    + ", "
                                    + node.startNode()
                                    + ", "
                                    + node.endNode()
                                    + ", "
                                    + node.distance()
                                    + ")");
                }
                counter++;
            }
        } catch (IOException | SQLException e) {
            throw new RuntimeException(e);
        }
    }
}
