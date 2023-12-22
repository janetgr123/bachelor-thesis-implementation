package ch.bt.benchmark;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class MethodVsSize {
    BufferedWriter fileWriter;
    CSVFormat csvFormat;
    CSVPrinter printer;

    public MethodVsSize(final String filename) throws IOException {
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
            final int sizeBasic,
            final int sizeBasicPar,
            final int sizeVH,
            final int sizeVHPar,
            final int sizeVHO,
            final int sizeVHOPar, final int sizeDP, final int sizeDPPar)
            throws IOException {
        printer.printRecord(
                dataSize, sizeBasic, sizeBasicPar, sizeVH, sizeVHPar, sizeVHO, sizeVHOPar, sizeDP, sizeDPPar);
    }
}
