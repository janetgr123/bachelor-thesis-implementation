package ch.bt.benchmark;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class ResultPrinter2 {
    BufferedWriter fileWriter;
    CSVFormat csvFormat;
    CSVPrinter printer;

    public ResultPrinter2(final String method) throws IOException {
        final String file = String.join(".", method, "csv");
        fileWriter =
                Files.newBufferedWriter(
                        Paths.get(String.join("/", "src/test/resources/data", file)),
                        StandardOpenOption.APPEND,
                        StandardOpenOption.CREATE);
        csvFormat =
                CSVFormat.DEFAULT
                        .builder()
                        //.setHeader("emm", "mode", "data size", "from", "range size", "time [ns]")
                        .build();
        printer = new CSVPrinter(fileWriter, csvFormat);
    }

    public void printToCsv(
            final String method,
            final String mode,
            final long timeInMillis,
            final int dataSize,
            final int rangeSize,
            final int from)
            throws IOException {
        printer.printRecord(method, mode, dataSize, from, rangeSize, timeInMillis);
    }
}
