package ch.bt.benchmark;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;

import java.io.*;
import java.util.*;

public class DataExtractor2 {
    private static final int MAX_NUMBER_OF_DATA_SAMPLES =
            BenchmarkSettings.MAX_NUMBER_OF_DATA_SAMPLES;
    private static final String PATH = "src/test/resources/benchmark";

    private static final List<String> classes =
            List.of(
                    "ch.bt.emm.basic.BasicEMM",
                    "ch.bt.emm.volumeHiding.VolumeHidingEMM",
                    "ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised");

    private static final List<String> MODES = List.of("seq", "par");
    private static final Map<String, List<String>> HEADERS = new HashMap<>();

    public static void main(String[] args) throws IOException {
        initializeHeaders();
        printTimeVersusDataSize("buildIndex");
        printOverheadVersusDataSize("overheadEncryptedIndex");
        printPercentagePaddingVersusDataSize("overheadEncryptedIndex");
        for (int i = 10; i <= MAX_NUMBER_OF_DATA_SAMPLES; i *= 10) {
            printTimeVersusRangeSizeForFixedDataSize("trapdoor", i);
            printTimeVersusRangeSizeForFixedDataSize("search", i);
            printPercentagePaddingVersusRangeSizeForFixedDataSize("searchPadding", i);
        }
    }

    private static void printPercentagePaddingVersusDataSize(final String method)
            throws IOException {
        final var writer =
                new MethodVsTime(method, String.join("-", method, "method-vs-percentage-padding"));
        for (int i = 10; i <= MAX_NUMBER_OF_DATA_SAMPLES; i *= 10) {
            final var current = String.join("/", PATH, String.join(".", method, "csv"));
            final var file = new File(current);
            if (file.exists()) {
                Reader in = new FileReader(current);
                CSVFormat csvFormat =
                        CSVFormat.DEFAULT
                                .builder()
                                .setHeader(HEADERS.get(method).toArray(String[]::new))
                                .setSkipHeaderRecord(true)
                                .build();
                Iterable<CSVRecord> records = csvFormat.parse(in);
                final var recordList = new ArrayList<CSVRecord>();
                records.forEach(recordList::add);
                final Map<String, Double> averagePercentagePadding = new HashMap<>();
                final int dataSize = i;
                classes.forEach(
                        clazz -> {
                            MODES.forEach(
                                    mode -> {
                                        final var recordsForDataSizeAndClass =
                                                recordList.stream()
                                                        .filter(
                                                                el ->
                                                                        el.get("data size")
                                                                                        .equals(
                                                                                                String
                                                                                                        .valueOf(
                                                                                                                dataSize))
                                                                                && el.get("emm")
                                                                                        .equals(
                                                                                                clazz)
                                                                                && el.get("mode")
                                                                                        .equals(
                                                                                                mode))
                                                        .toList();
                                        final var averageSize =
                                                ((double)
                                                                recordsForDataSizeAndClass.stream()
                                                                        .map(
                                                                                r ->
                                                                                        r.get(
                                                                                                "size encrypted index"))
                                                                        .map(Integer::parseInt)
                                                                        .reduce(Integer::sum)
                                                                        .orElse(0))
                                                        / recordsForDataSizeAndClass.size();
                                        final var averagePadding =
                                                ((double)
                                                                recordsForDataSizeAndClass.stream()
                                                                        .map(
                                                                                r ->
                                                                                        r.get(
                                                                                                "number of dummy values"))
                                                                        .map(Integer::parseInt)
                                                                        .reduce(Integer::sum)
                                                                        .orElse(0))
                                                        / recordsForDataSizeAndClass.size();
                                        averagePercentagePadding.put(
                                                String.join("-", clazz, mode),
                                                averagePadding / averageSize * 100);
                                    });
                        });
                writer.printToCsv(
                        dataSize,
                        averagePercentagePadding.get("ch.bt.emm.basic.BasicEMM-seq"),
                        averagePercentagePadding.get("ch.bt.emm.basic.BasicEMM-par"),
                        averagePercentagePadding.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-seq"),
                        averagePercentagePadding.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-par"),
                        averagePercentagePadding.get(
                                "ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-seq"),
                        averagePercentagePadding.get(
                                "ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-par"));
            }
        }
        writer.printer.close();
    }

    private static void printPercentagePaddingVersusRangeSizeForFixedDataSize(
            final String method, final int dataSize) throws IOException {
        final var writer =
                new MethodVsTime(
                        method,
                        String.join(
                                "-",
                                method,
                                "method-vs-percentage-padding",
                                String.valueOf(dataSize)));
        final var potenitalStep = dataSize / 20;
        final var step = potenitalStep == 0 ? 1 : potenitalStep;
        for (int i = step; i <= dataSize; i += step) {
            final var current = String.join("/", PATH, String.join(".", method, "csv"));
            final var file = new File(current);
            if (file.exists()) {
                Reader in = new FileReader(current);
                CSVFormat csvFormat =
                        CSVFormat.DEFAULT
                                .builder()
                                .setHeader(HEADERS.get(method).toArray(String[]::new))
                                .setSkipHeaderRecord(true)
                                .build();
                Iterable<CSVRecord> records = csvFormat.parse(in);
                final var recordList = new ArrayList<CSVRecord>();
                records.forEach(recordList::add);
                final Map<String, Double> averagePercentagePadding = new HashMap<>();
                final int rangeSize = i;
                classes.forEach(
                        clazz -> {
                            MODES.forEach(
                                    mode -> {
                                        final var recordsForDataSizeAndClass =
                                                recordList.stream()
                                                        .filter(
                                                                el ->
                                                                        el.get("data size")
                                                                                        .equals(
                                                                                                String
                                                                                                        .valueOf(
                                                                                                                dataSize))
                                                                                && el.get("emm")
                                                                                        .equals(
                                                                                                clazz)
                                                                                && el.get("mode")
                                                                                        .equals(
                                                                                                mode)
                                                                                && el.get(
                                                                                                "range size")
                                                                                        .equals(
                                                                                                String
                                                                                                        .valueOf(
                                                                                                                rangeSize)))
                                                        .toList();
                                        final var averageResponseSize =
                                                ((double)
                                                                recordsForDataSizeAndClass.stream()
                                                                        .map(
                                                                                r ->
                                                                                        r.get(
                                                                                                "size of response"))
                                                                        .map(Integer::parseInt)
                                                                        .reduce(Integer::sum)
                                                                        .orElse(0))
                                                        / recordsForDataSizeAndClass.size();
                                        final var averagePadding =
                                                ((double)
                                                                recordsForDataSizeAndClass.stream()
                                                                        .map(
                                                                                r ->
                                                                                        r.get(
                                                                                                "number of dummy values"))
                                                                        .map(Integer::parseInt)
                                                                        .reduce(Integer::sum)
                                                                        .orElse(0))
                                                        / recordsForDataSizeAndClass.size();
                                        averagePercentagePadding.put(
                                                String.join("-", clazz, mode),
                                                averagePadding / averageResponseSize * 100);
                                    });
                        });
                writer.printToCsv(
                        dataSize,
                        averagePercentagePadding.get("ch.bt.emm.basic.BasicEMM-seq"),
                        averagePercentagePadding.get("ch.bt.emm.basic.BasicEMM-par"),
                        averagePercentagePadding.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-seq"),
                        averagePercentagePadding.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-par"),
                        averagePercentagePadding.get(
                                "ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-seq"),
                        averagePercentagePadding.get(
                                "ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-par"));
            }
        }
        writer.printer.close();
    }

    private static void printTimeVersusRangeSizeForFixedDataSize(
            final String method, final int dataSize) throws IOException {
        final var writer =
                new MethodVsTime(
                        method,
                        String.join("-", method, "method-vs-time", String.valueOf(dataSize)));
        final var potenitalStep = dataSize / 20;
        final var step = potenitalStep == 0 ? 1 : potenitalStep;
        for (int i = step; i <= dataSize; i += step) {
            final var current = String.join("/", PATH, String.join(".", method, "csv"));
            final var file = new File(current);
            if (file.exists()) {
                Reader in = new FileReader(current);
                CSVFormat csvFormat =
                        CSVFormat.DEFAULT
                                .builder()
                                .setHeader(HEADERS.get(method).toArray(String[]::new))
                                .setSkipHeaderRecord(true)
                                .build();
                Iterable<CSVRecord> records = csvFormat.parse(in);
                final var recordList = new ArrayList<CSVRecord>();
                records.forEach(recordList::add);
                final Map<String, Double> averageTimes = new HashMap<>();
                final int rangeSize = i;
                classes.forEach(
                        clazz -> {
                            MODES.forEach(
                                    mode -> {
                                        final var recordsForDataSizeAndClass =
                                                recordList.stream()
                                                        .filter(
                                                                el ->
                                                                        el.get("data size")
                                                                                        .equals(
                                                                                                String
                                                                                                        .valueOf(
                                                                                                                dataSize))
                                                                                && el.get("emm")
                                                                                        .equals(
                                                                                                clazz)
                                                                                && el.get("mode")
                                                                                        .equals(
                                                                                                mode)
                                                                                && el.get(
                                                                                                "range size")
                                                                                        .equals(
                                                                                                String
                                                                                                        .valueOf(
                                                                                                                rangeSize)))
                                                        .toList();
                                        final var totalTime =
                                                recordsForDataSizeAndClass.stream()
                                                        .map(r -> r.get("time [ns]"))
                                                        .map(Long::parseLong)
                                                        .reduce(Long::sum)
                                                        .orElse(0L);
                                        averageTimes.put(
                                                String.join("-", clazz, mode),
                                                ((double) totalTime)
                                                        / recordsForDataSizeAndClass.size());
                                    });
                        });
                writer.printToCsv(
                        dataSize,
                        averageTimes.get("ch.bt.emm.basic.BasicEMM-seq"),
                        averageTimes.get("ch.bt.emm.basic.BasicEMM-par"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-seq"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-par"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-seq"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-par"));
            }
        }
        writer.printer.close();
    }

    private static void printOverheadVersusDataSize(final String method) throws IOException {
        final var writer = new MethodVsSize(method, String.join("-", method, "method-vs-overhead"));
        for (int i = 10; i <= MAX_NUMBER_OF_DATA_SAMPLES; i *= 10) {
            final var current = String.join("/", PATH, String.join(".", method, "csv"));
            final var file = new File(current);
            if (file.exists()) {
                Reader in = new FileReader(current);
                CSVFormat csvFormat =
                        CSVFormat.DEFAULT
                                .builder()
                                .setHeader(HEADERS.get(method).toArray(String[]::new))
                                .setSkipHeaderRecord(true)
                                .build();
                Iterable<CSVRecord> records = csvFormat.parse(in);
                final var recordList = new ArrayList<CSVRecord>();
                records.forEach(recordList::add);
                final var dataSize = i;
                final Map<String, Integer> averageSizes = new HashMap<>();
                classes.forEach(
                        clazz -> {
                            MODES.forEach(
                                    mode -> {
                                        final var recordsForDataSizeAndClass =
                                                recordList.stream()
                                                        .filter(
                                                                el ->
                                                                        el.get("data size")
                                                                                        .equals(
                                                                                                String
                                                                                                        .valueOf(
                                                                                                                dataSize))
                                                                                && el.get("emm")
                                                                                        .equals(
                                                                                                clazz)
                                                                                && el.get("mode")
                                                                                        .equals(
                                                                                                mode))
                                                        .toList();
                                        final var averageSize =
                                                recordsForDataSizeAndClass.stream()
                                                                .map(
                                                                        r ->
                                                                                r.get(
                                                                                        "size encrypted index"))
                                                                .map(Integer::parseInt)
                                                                .reduce(Integer::sum)
                                                                .orElse(0)
                                                        / recordsForDataSizeAndClass.size();
                                        averageSizes.put(
                                                String.join("-", clazz, mode), averageSize);
                                    });
                        });
                writer.printToCsv(
                        dataSize,
                        averageSizes.get("ch.bt.emm.basic.BasicEMM-seq"),
                        averageSizes.get("ch.bt.emm.basic.BasicEMM-par"),
                        averageSizes.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-seq"),
                        averageSizes.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-par"),
                        averageSizes.get("ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-seq"),
                        averageSizes.get("ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-par"));
            }
        }
        writer.printer.close();
    }

    private static void printTimeVersusDataSize(final String method) throws IOException {
        final var writer = new MethodVsTime(method, String.join("-", method, "method-vs-time"));
        for (int i = 10; i <= MAX_NUMBER_OF_DATA_SAMPLES; i *= 10) {
            final var current = String.join("/", PATH, String.join(".", method, "csv"));
            final var file = new File(current);
            if (file.exists()) {
                Reader in = new FileReader(current);
                CSVFormat csvFormat =
                        CSVFormat.DEFAULT
                                .builder()
                                .setHeader(HEADERS.get(method).toArray(String[]::new))
                                .setSkipHeaderRecord(true)
                                .build();
                Iterable<CSVRecord> records = csvFormat.parse(in);
                final var recordList = new ArrayList<CSVRecord>();
                records.forEach(recordList::add);
                final var dataSize = i;
                final Map<String, Double> averageTimes = new HashMap<>();
                classes.forEach(
                        clazz -> {
                            MODES.forEach(
                                    mode -> {
                                        final var recordsForDataSizeAndClass =
                                                recordList.stream()
                                                        .filter(
                                                                el ->
                                                                        el.get("data size")
                                                                                        .equals(
                                                                                                String
                                                                                                        .valueOf(
                                                                                                                dataSize))
                                                                                && el.get("emm")
                                                                                        .equals(
                                                                                                clazz)
                                                                                && el.get("mode")
                                                                                        .equals(
                                                                                                mode))
                                                        .toList();
                                        final var totalTime =
                                                recordsForDataSizeAndClass.stream()
                                                        .map(r -> r.get("time [ns]"))
                                                        .map(Long::parseLong)
                                                        .reduce(Long::sum)
                                                        .orElse(0L);
                                        averageTimes.put(
                                                String.join("-", clazz, mode),
                                                ((double) totalTime)
                                                        / recordsForDataSizeAndClass.size());
                                    });
                        });
                writer.printToCsv(
                        dataSize,
                        averageTimes.get("ch.bt.emm.basic.BasicEMM-seq"),
                        averageTimes.get("ch.bt.emm.basic.BasicEMM-par"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-seq"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-par"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-seq"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-par"));
            }
        }
        writer.printer.close();
    }

    private static void initializeHeaders() {
        HEADERS.put(
                "buildIndex",
                List.of("emm", "mode", "data size", "from", "range size", "time [ns]"));
        HEADERS.put(
                "trapdoor", List.of("emm", "mode", "data size", "from", "range size", "time [ns]"));
        HEADERS.put(
                "search", List.of("emm", "mode", "data size", "from", "range size", "time [ns]"));
        HEADERS.put(
                "searchPadding",
                List.of(
                        "emm",
                        "mode",
                        "data size",
                        "range size",
                        "size of response",
                        "number of dummy values"));
        HEADERS.put(
                "overheadEncryptedIndex",
                List.of(
                        "emm",
                        "mode",
                        "data size",
                        "size multimap",
                        "size encrypted index",
                        "number of dummy values"));
    }
}
