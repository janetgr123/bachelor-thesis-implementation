package ch.bt.benchmark;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;

import java.io.*;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DataExtractor {
    private static final int MAX_NUMBER_OF_DATA_SAMPLES =
            BenchmarkSettings.MAX_NUMBER_OF_DATA_SAMPLES;
    private static final String PATH = "src/test/resources/benchmark";

    private static final List<String> FOLDERS =
            List.of("baseline", "volumeHiding", "volumeHidingOpt", "dpVolumeHiding");
    private static final List<String> MODES = List.of("parallel", "sequential");
    private static final List<String> METHODS = List.of("buildIndex", "trapdoor", "search");
    private static final Map<String, List<String>> HEADERS = new HashMap<>();

    public static void main(String[] args) throws IOException {
        initializeHeaders();

        for (final var mode : MODES) {
            for (final var folder : FOLDERS) {
                for (final var method : METHODS) {
                    final var writer = new ResultPrinter(method, folder, mode, "data-versus-score-final");
                    final var writer2 =
                            new ResultPrinter(method, folder, mode, "range-versus-score");
                    for (int i = 10; i <= MAX_NUMBER_OF_DATA_SAMPLES; i *= 10) {
                        final var current =
                                String.join(
                                        "/",
                                        PATH,
                                        folder,
                                        mode,
                                        "results",
                                        String.join(
                                                "-",
                                                "benchmark-results",
                                                String.join(
                                                        "", method, String.valueOf(i), ".csv")));
                        final var file = new File(current);
                        if (file.exists()) {
                            Reader in = new FileReader(current);
                            CSVFormat csvFormat =
                                    CSVFormat.DEFAULT
                                            .builder()
                                            .setHeader(
                                                    HEADERS.get(method).stream()
                                                            .toArray(String[]::new))
                                            .setSkipHeaderRecord(true)
                                            .build();
                            Iterable<CSVRecord> records = csvFormat.parse(in);
                            Reader in2 = new FileReader(current);
                            Iterable<CSVRecord> records2 = csvFormat.parse(in2);
                            printDataScore(writer, records);
                            if (!method.equals("buildIndex")) {
                                printRangeScore(writer2, records2);
                            }
                        }
                    }
                    writer.printer.close();
                    writer2.printer.close();
                    final var writer3 =
                            new ResultPrinter(method, folder, mode, "range-versus-score-final");
                    final var current =
                            String.join(
                                    "/",
                                    PATH,
                                    folder,
                                    mode,
                                    String.join(
                                            "-",
                                            "data",
                                            method,
                                            String.join("", "range-versus-score", ".csv")));
                    final var file = new File(current);
                    if (file.exists()) {
                        Reader in = new FileReader(current);
                        CSVFormat csvFormat =
                                CSVFormat.DEFAULT.builder().setSkipHeaderRecord(true).build();
                        Iterable<CSVRecord> records = csvFormat.parse(in);
                        printRangeScore2(writer3, records);
                    }
                    writer3.printer.close();
                }
            }
        }
    }

    private static void printRangeScore(
            final ResultPrinter writer, final Iterable<CSVRecord> records) {
        final Map<String, List<Double>> map = new HashMap<>();
        for (final var record : records) {
            final var size = record.get("Param: size");
            if (map.containsKey(size)) {
                final var list = new ArrayList<>(map.get(size));
                list.add(Double.parseDouble(record.get("Score")));
                map.put(size, list);
            } else {
                map.put(size, List.of(Double.parseDouble(record.get("Score"))));
            }
        }
        final var keys = map.keySet();
        for (final var key : keys) {
            final var averageScore =
                    String.valueOf(map.get(key).stream().reduce(Double::sum).orElse(0.0));
            try {
                writer.printToCsv(key, averageScore);
            } catch (IOException | SQLException | GeneralSecurityException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static void printRangeScore2(
            final ResultPrinter writer, final Iterable<CSVRecord> records) {
        final Map<String, List<Double>> map = new HashMap<>();
        for (final var record : records) {
            final var size = record.get(0);
            if (map.containsKey(size)) {
                final var list = new ArrayList<>(map.get(size));
                list.add(Double.parseDouble(record.get(1)));
                map.put(size, list);
            } else {
                map.put(size, List.of(Double.parseDouble(record.get(1))));
            }
        }
        final var keys = map.keySet();
        for (final var key : keys) {
            final var averageScore =
                    String.valueOf(map.get(key).stream().reduce(Double::sum).orElse(0.0));
            try {
                writer.printToCsv(key, averageScore);
            } catch (IOException | SQLException | GeneralSecurityException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static void printDataScore(
            final ResultPrinter writer, final Iterable<CSVRecord> records) {
        double scoreSum = 0;
        int size = 0;
        var data = "";
        for (final var record : records) {
            scoreSum += Double.parseDouble(record.get("Score"));
            size++;
            data = record.get("Param: numberOfDataSamples");
        }
        final var averageScore = String.valueOf(scoreSum / size);
        try {
            writer.printToCsv(data, averageScore);
        } catch (IOException | SQLException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static void initializeHeaders() {
        HEADERS.put(
                "buildIndex",
                List.of(
                        "Benchmark",
                        "Mode",
                        "Threads",
                        "Samples",
                        "Score",
                        "Score Error (99.9%)",
                        "Unit",
                        "Param: numberOfDataSamples"));
        HEADERS.put(
                "trapdoor",
                List.of(
                        "Benchmark",
                        "Mode",
                        "Threads",
                        "Samples",
                        "Score",
                        "Score Error (100.9%)",
                        "Unit",
                        "Param: from",
                        "Param: numberOfDataSamples",
                        "Param: size"));
        HEADERS.put(
                "search",
                List.of(
                        "Benchmark",
                        "Mode",
                        "Threads",
                        "Samples",
                        "Score",
                        "Score Error (99.9%)",
                        "Unit",
                        "Param: from",
                        "Param: numberOfDataSamples",
                        "Param: size"));
    }
}
