package ch.bt.benchmark;

import ch.bt.model.db.NetworkNode;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexMap;
import ch.bt.model.encryptedindex.EncryptedIndexTables;
import ch.bt.model.multimap.CiphertextWithIV;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.PairLabelCiphertext;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.qos.logback.core.encoder.ByteArrayUtil;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.VerboseMode;
import org.openjdk.jmh.runner.options.WarmupMode;

import java.io.*;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

public class BenchmarkUtils {
    public static Options createOptionsForSearch(
            final String folder, final String mode, final int dataSize) {
        final var ranges =
                IntStream.iterate(dataSize / 5, i -> i <= dataSize, i -> i + dataSize / 5)
                        .mapToObj(String::valueOf)
                        .toArray(String[]::new);
        String clazz = String.valueOf(folder.charAt(0)).toUpperCase() + folder.substring(1);
        if (mode.equals("parallel")) {
            clazz = String.join("", clazz, "Par");
        }
        final String logs = String.join("", "benchmark-logs-", "search", ".txt");
        final String results = String.join("", "benchmark-results-", "search", ".csv");

        System.out.println("Preparing " + clazz + " trapdoor");

        return new OptionsBuilder()
                .jvmArgsPrepend("-server")
                .include(Search.class.getName())
                .param("numberOfDataSamples", String.valueOf(dataSize))
                .param("rangeSize", ranges)
                .param("type", folder)
                .mode(Mode.AverageTime)
                .timeUnit(TimeUnit.MILLISECONDS)
                .warmupMode(WarmupMode.INDI)
                .warmupIterations(BenchmarkSettings.WARM_UPS)
                .measurementIterations(BenchmarkSettings.NUMBER_OF_QUERIES)
                .forks(BenchmarkSettings.FORKS)
                .resultFormat(ResultFormatType.CSV)
                .result(
                        String.join(
                                "/", BenchmarkSettings.FOLDER, folder, mode, "results", results))
                .verbosity(VerboseMode.EXTRA)
                .output(String.join("/", BenchmarkSettings.FOLDER, folder, mode, "logs", logs))
                .build();
    }

    public static Options createOptionsForTrapdoor(
            final String folder, final String mode, final int dataSize) {
        final var ranges =
                IntStream.iterate(dataSize / 5, i -> i <= dataSize, i -> i + dataSize / 5)
                        .mapToObj(String::valueOf)
                        .toArray(String[]::new);
        String clazz = String.valueOf(folder.charAt(0)).toUpperCase() + folder.substring(1);
        if (mode.equals("parallel")) {
            clazz = String.join("", clazz, "Par");
        }
        final String logs = String.join("", "benchmark-logs-", "trapdoor", ".txt");
        final String results = String.join("", "benchmark-results-", "trapdoor", ".csv");

        System.out.println("Preparing " + clazz + " trapdoor");

        return new OptionsBuilder()
                .jvmArgsPrepend("-server")
                .include(Trapdoor.class.getName())
                .param("numberOfDataSamples", String.valueOf(dataSize))
                .param("rangeSize", ranges)
                .param("type", folder)
                .mode(Mode.AverageTime)
                .timeUnit(TimeUnit.NANOSECONDS)
                .warmupMode(WarmupMode.INDI)
                .warmupIterations(BenchmarkSettings.WARM_UPS)
                .measurementIterations(BenchmarkSettings.NUMBER_OF_QUERIES)
                .forks(BenchmarkSettings.FORKS)
                .resultFormat(ResultFormatType.CSV)
                .result(
                        String.join(
                                "/", BenchmarkSettings.FOLDER, folder, mode, "results", results))
                .verbosity(VerboseMode.EXTRA)
                .output(String.join("/", BenchmarkSettings.FOLDER, folder, mode, "logs", logs))
                .build();
    }

    public static Options createOptionsForBuildIndex(final String folder, final String mode) {
        String clazz = String.valueOf(folder.charAt(0)).toUpperCase() + folder.substring(1);
        if (mode.equals("parallel")) {
            clazz = String.join("", clazz, "Par");
        }
        final String logs = String.join("", "benchmark-logs-", "buildIndex", ".txt");
        final String results = String.join("", "benchmark-results-", "buildIndex", ".csv");

        System.out.println("Preparing " + clazz + " build index");

        return new OptionsBuilder()
                .jvmArgsPrepend("-server")
                .include(BuildIndex.class.getName())
                .param(
                        "numberOfDataSamples",
                        IntStream.iterate(
                                        10,
                                        i -> i <= BenchmarkSettings.MAX_NUMBER_OF_DATA_SAMPLES,
                                        i -> 10 * i)
                                .mapToObj(String::valueOf)
                                .toArray(String[]::new))
                .param("type", folder)
                .mode(Mode.AverageTime)
                .timeUnit(TimeUnit.MILLISECONDS)
                .warmupMode(WarmupMode.INDI)
                .warmupIterations(BenchmarkSettings.WARM_UPS)
                .measurementIterations(BenchmarkSettings.NUMBER_OF_ITERATIONS_BUILD_INDEX)
                .forks(BenchmarkSettings.FORKS)
                .resultFormat(ResultFormatType.CSV)
                .result(
                        String.join(
                                "/", BenchmarkSettings.FOLDER, folder, mode, "results", results))
                .verbosity(VerboseMode.EXTRA)
                .output(String.join("/", BenchmarkSettings.FOLDER, folder, mode, "logs", logs))
                .build();
    }

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

    public static Vertex readRoot(final int dataSize, final String type) throws IOException {
        final var current =
                String.join(
                        "/", BenchmarkSettings.FOLDER, String.join("-", "root", "build-index.csv"));
        final var file = new File(current);
        if (file.exists()) {
            Reader in = new FileReader(current);
            CSVFormat csvFormat =
                    CSVFormat.DEFAULT
                            .builder()
                            .setHeader("type", "data size", "root id", "root from", "root to")
                            .setSkipHeaderRecord(true)
                            .build();
            Iterable<CSVRecord> records = csvFormat.parse(in);
            List<CSVRecord> recordList = new ArrayList<>();
            records.forEach(record -> recordList.add(record));
            final var entry =
                    recordList.stream()
                            .filter(
                                    el ->
                                            el.get("type").equals(type)
                                                    && el.get("data size")
                                                            .equals(String.valueOf(dataSize)))
                            .toList()
                            .get(0);
            return new Vertex(
                    entry.get("root id"),
                    new CustomRange(
                            Integer.parseInt(entry.get("root from")),
                            Integer.parseInt(entry.get("root to"))));
        }
        return null;
    }

    public static EncryptedIndex extractIndex(final int dataSize, final String type)
            throws IOException {
        EncryptedIndex result = null;
        final var current =
                String.join(
                        "/",
                        BenchmarkSettings.FOLDER,
                        type,
                        "sequential",
                        "encryptedIndex",
                        String.join("-", "benchmark-results", "build-index.csv"));
        final var file = new File(current);
        if (file.exists()) {
            Reader in = new FileReader(current);
            CSVFormat csvFormat =
                    CSVFormat.DEFAULT
                            .builder()
                            .setHeader(
                                    "type",
                                    "data size",
                                    "label data",
                                    "label iv",
                                    "value1 data",
                                    "value1 iv")
                            .setSkipHeaderRecord(true)
                            .build();
            Iterable<CSVRecord> records = csvFormat.parse(in);
            List<CSVRecord> recordList = new ArrayList<>();
            records.forEach(record -> recordList.add(record));
            final var entries =
                    recordList.stream()
                            .filter(
                                    el ->
                                            el.get("type").equals(type)
                                                    && el.get("data size")
                                                            .equals(String.valueOf(dataSize)))
                            .toList();
            final var map = new HashMap<Label, CiphertextWithIV>();
            final var table1 = new ArrayList<PairLabelCiphertext>();
            final var table2 = new ArrayList<PairLabelCiphertext>();
            for (final var entry : entries) {
                final var label =
                        switch (type) {
                            case "volumeHiding", "volumeHidingOpt" -> new CiphertextWithIV(
                                    ByteArrayUtil.hexStringToByteArray(entry.get("label iv")),
                                    ByteArrayUtil.hexStringToByteArray(entry.get("label data")));
                            default -> new Label(
                                    ByteArrayUtil.hexStringToByteArray(entry.get("label data")));
                        };
                final var value =
                        new CiphertextWithIV(
                                ByteArrayUtil.hexStringToByteArray(entry.get("value1 iv")),
                                ByteArrayUtil.hexStringToByteArray(entry.get("value1 data")));
                switch (type) {
                    case "volumeHiding", "volumeHidingOpt":
                        boolean tableNumber =
                                entry.get("tableNumber").equals("0")
                                        ? table1.add(
                                                new PairLabelCiphertext(
                                                        (CiphertextWithIV) label, value))
                                        : table2.add(
                                                new PairLabelCiphertext(
                                                        (CiphertextWithIV) label, value));
                        break;
                    default:
                        map.put((Label) label, value);
                }
                result =
                        switch (type) {
                            case "volumeHiding", "volumeHidingOpt" -> new EncryptedIndexTables(
                                    table1.toArray(PairLabelCiphertext[]::new),
                                    table2.toArray(PairLabelCiphertext[]::new));
                            default -> new EncryptedIndexMap(map);
                        };
            }
        }
        return result;
    }
}
