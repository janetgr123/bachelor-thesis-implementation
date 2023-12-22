package ch.bt.benchmark;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;

public class MethodVsTime {
    BufferedWriter fileWriter;
    CSVFormat csvFormat;
    CSVPrinter printer;

    public MethodVsTime(final String method, final String filename) throws IOException {
        final String file = String.join(".", filename, "csv");
        fileWriter =
                Files.newBufferedWriter(
                        Paths.get(String.join("/", "src/test/resources/benchmark", file)),
                        StandardOpenOption.APPEND,
                        StandardOpenOption.CREATE);
        csvFormat = CSVFormat.DEFAULT.builder().build();
        printer = new CSVPrinter(fileWriter, csvFormat);
    }

    public void printToCsv(
            final int dataSize,
            final double timeBasic,
            final double timeBasicPar,
            final double timeVH,
            final double timeVHPar,
            final double timeVHO,
            final double timeVHOPar)
            throws IOException {
        printer.printRecord(
                dataSize, timeBasic, timeBasicPar, timeVH, timeVHPar, timeVHO, timeVHOPar);
    }
}
