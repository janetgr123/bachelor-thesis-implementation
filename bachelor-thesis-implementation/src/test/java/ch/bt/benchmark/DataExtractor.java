package ch.bt.benchmark;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;

import java.io.*;
import java.text.NumberFormat;
import java.util.*;

/**
 * This class extracts the data for the plots from the benchmark results.
 *
 * @author Janet Greutmann
 */
public class DataExtractor {
    private static final int MAX_NUMBER_OF_DATA_SAMPLES =
            BenchmarkSettings.MAX_NUMBER_OF_DATA_SAMPLES;
    private static final String PATH = "src/test/resources/data";

    private static final List<String> classes =
            List.of(
                    "ch.bt.emm.basic.BasicEMM",
                    "ch.bt.emm.volumeHiding.VolumeHidingEMM",
                    "ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised",
                    "ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM");

    private static final List<String> MODES = List.of("seq", "par");
    private static final Map<String, List<String>> HEADERS = new HashMap<>();
    private static final NumberFormat nf = NumberFormat.getPercentInstance(new Locale("en", "US"));

    public static void main(String[] args) throws IOException {
        initializeHeaders();
        printTimeVersusDataSize("buildIndex");
        printOverheadVersusDataSize("overheadEncryptedIndex");
        printPercentagePaddingVersusDataSize("overheadEncryptedIndex");
        for (int i = 10; i <= MAX_NUMBER_OF_DATA_SAMPLES; i += 10) {
            printTimeVersusRangeSizeForFixedDataSize("trapdoor", i);
            printTimeVersusRangeSizeForFixedDataSize("search", i);
            printPercentagePaddingVersusRangeSizeForFixedDataSize("searchPadding", i);
            printTimeVersusRangeSizeForFixedDataSize("trapdoor2", i);
            printTimeVersusRangeSizeForFixedDataSize("search2", i);
            printPercentagePaddingVersusRangeSizeForFixedDataSize("searchPadding2", i);
        }
    }

    private static void printPercentagePaddingVersusDataSize(final String method)
            throws IOException {
        final var writer =
                new MethodVsPadding(String.join("-", method, "method-vs-percentage-padding"));
        for (int i = 10; i <= MAX_NUMBER_OF_DATA_SAMPLES; i += 10) {
            final var current = String.join("/", PATH, String.join(".", method, "csv"));
            final var file = new File(current);
            if (file.exists()) {
                Reader in = new FileReader(current);
                CSVFormat csvFormat =
                        CSVFormat.DEFAULT
                                .builder()
                                .setHeader(HEADERS.get(method).toArray(String[]::new))
                                .build();
                Iterable<CSVRecord> records = csvFormat.parse(in);
                final var recordList = new ArrayList<CSVRecord>();
                records.forEach(recordList::add);
                final Map<String, Double> averagePercentagePadding = new HashMap<>();
                final int dataSize = i;
                classes.forEach(
                        clazz -> {
                            final var recordsForDataSizeAndClass =
                                    recordList.stream()
                                            .filter(
                                                    el ->
                                                            el.get("data size")
                                                                            .equals(
                                                                                    String.valueOf(
                                                                                            dataSize))
                                                                    && el.get("emm").equals(clazz)
                                                                    && el.get("mode").equals("seq"))
                                            .toList();
                            final var averageSize =
                                    ((double)
                                                    recordsForDataSizeAndClass.stream()
                                                            .map(r -> r.get("size encrypted index"))
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
                            averagePercentagePadding.put(clazz, averagePadding / averageSize);
                        });
                writer.printToCsv(
                        dataSize,
                        nf.format(
                                        averagePercentagePadding
                                                .get("ch.bt.emm.basic.BasicEMM")
                                                .doubleValue())
                                .replace("%", "\\%"),
                        nf.format(
                                        averagePercentagePadding
                                                .get("ch.bt.emm.volumeHiding.VolumeHidingEMM")
                                                .doubleValue())
                                .replace("%", "\\%"),
                        nf.format(
                                        averagePercentagePadding
                                                .get(
                                                        "ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised")
                                                .doubleValue())
                                .replace("%", "\\%"),
                        nf.format(
                                        averagePercentagePadding
                                                .get(
                                                        "ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM")
                                                .doubleValue())
                                .replace("%", "\\%"));
            }
        }
        writer.printer.close();
    }

    private static void printPercentagePaddingVersusRangeSizeForFixedDataSize(
            final String method, final int dataSize) throws IOException {
        final var writer =
                new MethodVsPadding2(
                        String.join(
                                "-",
                                method,
                                "method-vs-percentage-padding",
                                String.valueOf(dataSize)));
        final var writer2 =
                new MethodVsPadding2(
                        String.join(
                                "-",
                                method,
                                "method-vs-percentage-padding-no-percent",
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
                                .build();
                Iterable<CSVRecord> records = csvFormat.parse(in);
                final var recordList = new ArrayList<CSVRecord>();
                records.forEach(recordList::add);
                final Map<String, Double> averagePercentagePadding = new HashMap<>();
                final int rangeSize = i;
                classes.forEach(
                        clazz -> {
                            final var recordsForDataSizeAndClass =
                                    recordList.stream()
                                            .filter(
                                                    el ->
                                                            el.get("data size")
                                                                            .equals(
                                                                                    String.valueOf(
                                                                                            dataSize))
                                                                    && el.get("emm").equals(clazz)
                                                                    && el.get("mode").equals("seq")
                                                                    && el.get("range size")
                                                                            .equals(
                                                                                    String.valueOf(
                                                                                            rangeSize)))
                                            .toList();
                            final var averageResponseSize =
                                    ((double)
                                                    recordsForDataSizeAndClass.stream()
                                                            .map(r -> r.get("size of response"))
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
                                    clazz, averagePadding / averageResponseSize);
                        });
                writer.printToCsv(
                        rangeSize,
                        nf.format(
                                        averagePercentagePadding
                                                .get("ch.bt.emm.basic.BasicEMM")
                                                .doubleValue())
                                .replace("%", "\\%"),
                        nf.format(
                                        averagePercentagePadding
                                                .get("ch.bt.emm.volumeHiding.VolumeHidingEMM")
                                                .doubleValue())
                                .replace("%", "\\%"),
                        nf.format(
                                        averagePercentagePadding
                                                .get(
                                                        "ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised")
                                                .doubleValue())
                                .replace("%", "\\%"),
                        nf.format(
                                        averagePercentagePadding
                                                .get(
                                                        "ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM")
                                                .doubleValue())
                                .replace("%", "\\%"));
                writer2.printToCsv(
                        rangeSize,
                        nf.format(
                                        averagePercentagePadding
                                                .get("ch.bt.emm.basic.BasicEMM")
                                                .doubleValue())
                                .replace("%", ""),
                        nf.format(
                                        averagePercentagePadding
                                                .get("ch.bt.emm.volumeHiding.VolumeHidingEMM")
                                                .doubleValue())
                                .replace("%", ""),
                        nf.format(
                                        averagePercentagePadding
                                                .get(
                                                        "ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised")
                                                .doubleValue())
                                .replace("%", ""),
                        nf.format(
                                        averagePercentagePadding
                                                .get(
                                                        "ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM")
                                                .doubleValue())
                                .replace("%", ""));
            }
        }
        writer.printer.close();
        writer2.printer.close();
    }

    private static void printTimeVersusRangeSizeForFixedDataSize(
            final String method, final int dataSize) throws IOException {
        final var writer =
                new MethodVsTime(
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
                                .build();
                Iterable<CSVRecord> records = csvFormat.parse(in);
                final var recordList = new ArrayList<CSVRecord>();
                records.forEach(recordList::add);
                final Map<String, Double> averageTimes = new HashMap<>();
                final int rangeSize = i;
                classes.forEach(
                        clazz ->
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
                                                                                    && el.get(
                                                                                                    "mode")
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
                                        }));
                writer.printToCsv(
                        rangeSize,
                        averageTimes.get("ch.bt.emm.basic.BasicEMM-seq"),
                        averageTimes.get("ch.bt.emm.basic.BasicEMM-par"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-seq"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-par"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-seq"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-par"),
                        averageTimes.get(
                                "ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM-seq"),
                        averageTimes.get(
                                "ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM-par"));
            }
        }
        writer.printer.close();
    }

    private static void printOverheadVersusDataSize(final String method) throws IOException {
        final var writer = new MethodVsSize(String.join("-", method, "method-vs-overhead"));
        for (int i = 10; i <= MAX_NUMBER_OF_DATA_SAMPLES; i += 10) {
            final var current = String.join("/", PATH, String.join(".", method, "csv"));
            final var file = new File(current);
            if (file.exists()) {
                Reader in = new FileReader(current);
                CSVFormat csvFormat =
                        CSVFormat.DEFAULT
                                .builder()
                                .setHeader(HEADERS.get(method).toArray(String[]::new))
                                .build();
                Iterable<CSVRecord> records = csvFormat.parse(in);
                final var recordList = new ArrayList<CSVRecord>();
                records.forEach(recordList::add);
                final var dataSize = i;
                final Map<String, Integer> averageSizes = new HashMap<>();
                classes.forEach(
                        clazz ->
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
                                                                                    && el.get(
                                                                                                    "mode")
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
                                        }));
                writer.printToCsv(
                        dataSize,
                        averageSizes.get("ch.bt.emm.basic.BasicEMM-seq"),
                        averageSizes.get("ch.bt.emm.basic.BasicEMM-par"),
                        averageSizes.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-seq"),
                        averageSizes.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-par"),
                        averageSizes.get("ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-seq"),
                        averageSizes.get("ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-par"),
                        averageSizes.get(
                                "ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM-seq"),
                        averageSizes.get(
                                "ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM-par"));
            }
        }
        writer.printer.close();
    }

    private static void printTimeVersusDataSize(final String method) throws IOException {
        final var writer = new MethodVsTime(String.join("-", method, "method-vs-time"));
        for (int i = 10; i <= MAX_NUMBER_OF_DATA_SAMPLES; i += 10) {
            final var current = String.join("/", PATH, String.join(".", method, "csv"));
            final var file = new File(current);
            if (file.exists()) {
                Reader in = new FileReader(current);
                CSVFormat csvFormat =
                        CSVFormat.DEFAULT
                                .builder()
                                .setHeader(HEADERS.get(method).toArray(String[]::new))
                                .build();
                Iterable<CSVRecord> records = csvFormat.parse(in);
                final var recordList = new ArrayList<CSVRecord>();
                records.forEach(recordList::add);
                final var dataSize = i;
                final Map<String, Double> averageTimes = new HashMap<>();
                classes.forEach(
                        clazz ->
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
                                                                                    && el.get(
                                                                                                    "mode")
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
                                        }));
                writer.printToCsv(
                        dataSize,
                        averageTimes.get("ch.bt.emm.basic.BasicEMM-seq"),
                        averageTimes.get("ch.bt.emm.basic.BasicEMM-par"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-seq"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMM-par"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-seq"),
                        averageTimes.get("ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised-par"),
                        averageTimes.get(
                                "ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM-seq"),
                        averageTimes.get(
                                "ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM-par"));
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
                "trapdoor2",
                List.of("emm", "mode", "data size", "from", "range size", "time [ns]"));
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
                "search2", List.of("emm", "mode", "data size", "from", "range size", "time [ns]"));
        HEADERS.put(
                "searchPadding2",
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
