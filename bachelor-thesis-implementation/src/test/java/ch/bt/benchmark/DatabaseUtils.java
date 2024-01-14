package ch.bt.benchmark;

import ch.bt.model.db.Node;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;

import java.io.*;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;

/**
 * This class is collection of static helper methods to read the dataset.
 *
 * @author Janet Greutmann
 */
public class DatabaseUtils {
    public static void addData1(final Connection connection) throws IOException, SQLException {
        final var current = "src/main/resources/data/data.csv";
        final var file = new File(current);
        if (file.exists()) {
            Reader in = new FileReader(current);
            CSVFormat csvFormat = CSVFormat.DEFAULT.builder().setDelimiter(" ").build();
            Iterable<CSVRecord> records = csvFormat.parse(in);
            final var recordList = new ArrayList<Node>();
            records.forEach(
                    record -> {
                        if (recordList.size()
                                <= 1.5
                                        * BenchmarkSettings
                                                .MAX_NUMBER_OF_DATA_SAMPLES) { // change domain size
                            if (record.size() > 2 && !record.get(2).isEmpty()) {
                                recordList.add(
                                        new Node(
                                                Integer.parseInt(record.get(0)),
                                                Double.parseDouble(record.get(2)),
                                                Double.parseDouble(record.get(1))));
                            }
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

    public static void addData2(final Connection connection) throws IOException, SQLException {
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

    public static void addData3(final Connection connection) throws IOException, SQLException {
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
