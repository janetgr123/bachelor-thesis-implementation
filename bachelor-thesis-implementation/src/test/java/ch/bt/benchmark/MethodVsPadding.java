package ch.bt.benchmark;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class MethodVsPadding {
    BufferedWriter fileWriter;
    CSVFormat csvFormat;
    CSVPrinter printer;

    public MethodVsPadding(final String filename) throws IOException {
        final String file = String.join(".", filename, "csv");
        fileWriter =
                Files.newBufferedWriter(
                        Paths.get(String.join("/", "src/test/resources/data", file)),
                        StandardOpenOption.APPEND,
                        StandardOpenOption.CREATE);
        csvFormat =
                CSVFormat.DEFAULT
                        .builder()
                        .setHeader(
                                "data size",
                                "baseline",
                                "volume hiding",
                                "volume hiding opt",
                                "dp volume hiding")
                        .build();
        printer = new CSVPrinter(fileWriter, csvFormat);
    }

    public void printToCsv(
            final int dataSize,
            final String timeBasic,
            final String timeVH,
            final String timeVHO,
            final String timeDP)
            throws IOException {
        printer.printRecord(dataSize, timeBasic, timeVH, timeVHO, timeDP);
    }
}
