package ch.bt;

import ch.bt.model.db.Node;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
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
import java.util.ArrayList;

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
    public void beforeAll(ExtensionContext extensionContext) throws SQLException, IOException {
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
            addData1();
            //addData2();
            //addData3(); because very slow
            TestUtils.init(connection);
            extensionContext
                    .getRoot()
                    .getStore(ExtensionContext.Namespace.GLOBAL)
                    .put("test configurations with db", this);
        }
    }

    private void addData1() throws IOException, SQLException {
        final var current = "src/main/resources/data/data.csv";
        final var file = new File(current);
        if (file.exists()) {
            Reader in = new FileReader(current);
            CSVFormat csvFormat = CSVFormat.DEFAULT.builder().setDelimiter(" ").build();
            Iterable<CSVRecord> records = csvFormat.parse(in);
            final var recordList = new ArrayList<Node>();
            records.forEach(
                    record -> {
                        if (record.size() > 2 && !record.get(2).isEmpty()) {
                            recordList.add(
                                    new Node(
                                            Integer.parseInt(record.get(0)),
                                            Double.parseDouble(record.get(2)),
                                            Double.parseDouble(record.get(1))));
                        }
                    });

            int counter = 0;
            Statement stmt = null;
            for (final var node : recordList) {
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
        }
    }

    private void addData2() throws IOException, SQLException {
        final var current = "src/main/resources/data/VDS_MS_310809_27_0210.csv";
        final var file = new File(current);
        if (file.exists()) {
            Reader in = new FileReader(current);
            CSVFormat csvFormat = CSVFormat.DEFAULT.builder().build();
            Iterable<CSVRecord> records = csvFormat.parse(in);
            final var recordList = new ArrayList<Node>();
            records.forEach(
                    record -> {
                        if (record.size() > 4
                                && !record.get(5).equals("Breite")
                                && !record.get(5).isEmpty()) {
                            recordList.add(
                                    new Node(
                                            (int) record.getRecordNumber(),
                                            Double.parseDouble(record.get(5)),
                                            Double.parseDouble(record.get(4))));
                        }
                    });

            int counter = 0;
            Statement stmt = null;
            for (final var node : recordList) {
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
                            "insert into test.public.t_spitz (latitude, longitude) VALUES ("
                                    + node.latitude()
                                    + ", "
                                    + node.longitude()
                                    + ")");
                }
                counter++;
            }
        }
    }

    private void addData3() throws IOException, SQLException {
        final var current = "src/main/resources/data/Gowalla_totalCheckins.txt";
        final var file = new File(current);
        if (file.exists()) {
            Reader in = new FileReader(current);
            CSVFormat csvFormat = CSVFormat.DEFAULT.builder().setDelimiter("\t").build();
            Iterable<CSVRecord> records = csvFormat.parse(in);
            final var recordList = new ArrayList<Node>();
            records.forEach(
                    record -> {
                        if (record.size() > 4 && !record.get(3).isEmpty()) {
                            recordList.add(
                                    new Node(
                                            (int) record.getRecordNumber(),
                                            Double.parseDouble(record.get(2)),
                                            Double.parseDouble(record.get(3))));
                        }
                    });

            int counter = 0;
            Statement stmt = null;
            for (final var node : recordList) {
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
                            "insert into test.public.t_check_ins (latitude, longitude) VALUES ("
                                    + node.latitude()
                                    + ", "
                                    + node.longitude()
                                    + ")");
                }
                counter++;
            }
        }
    }
}
