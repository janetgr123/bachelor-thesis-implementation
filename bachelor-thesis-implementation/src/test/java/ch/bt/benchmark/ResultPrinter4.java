package ch.bt.benchmark;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * This class writes the response size benchmark results
 *
 * @author Janet Greutmann
 */
public class ResultPrinter4 {
    BufferedWriter fileWriter;
    CSVFormat csvFormat;
    CSVPrinter printer;

    public ResultPrinter4(final String method, final int k) throws IOException {
        final String file = String.join(".", (method + "-" + k), "csv");
        fileWriter =
                Files.newBufferedWriter(
                        Paths.get(String.join("/", "src/test/resources/data2", file)),
                        StandardOpenOption.APPEND,
                        StandardOpenOption.CREATE);
        csvFormat =
                CSVFormat.DEFAULT
                        .builder()
                        .setHeader(
                                "emm",
                                "mode",
                                "data size",
                                "range size",
                                "size of response",
                                "number of dummy values")
                        .build();
        printer = new CSVPrinter(fileWriter, csvFormat);
    }

    public void printToCsv(
            final String method,
            final String mode,
            final int dataSize,
            final int rangeSize,
            final int responseSize,
            final long dummies)
            throws IOException {
        printer.printRecord(method, mode, dataSize, rangeSize, responseSize, dummies);
    }
}
