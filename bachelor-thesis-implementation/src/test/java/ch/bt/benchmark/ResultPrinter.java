package ch.bt.benchmark;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public class ResultPrinter {
    BufferedWriter fileWriter;
    CSVFormat csvFormat;
    CSVPrinter printer;

    public ResultPrinter(final String method, final String folder) throws IOException {
        final String file = String.join(".", String.join("-", "data", method), "csv");
        fileWriter =
                Files.newBufferedWriter(
                        Paths.get(String.join("/", folder, file)),
                        StandardOpenOption.APPEND,
                        StandardOpenOption.CREATE);
        csvFormat = CSVFormat.DEFAULT.builder().build();
        printer = new CSVPrinter(fileWriter, csvFormat);
    }

    public void printToCsv(final int dataSize, final Double queryTime)
            throws IOException, SQLException, GeneralSecurityException {
        printer.printRecord(dataSize, queryTime);
    }
}
