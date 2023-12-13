package ch.bt.benchmark;

import ch.bt.model.db.NetworkNode;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;

import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class BenchmarkUtils {
    public static void addData(Connection connection) {
        try (final var input = BenchmarkUtils.class.getResourceAsStream("/data/data.csv")) {
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


}


