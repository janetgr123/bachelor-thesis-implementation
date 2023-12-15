package ch.bt.benchmark;

import ch.bt.emm.basic.BasicEMM;
import ch.bt.genericRs.RangeBRCScheme;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.searchtoken.SearchTokenBytes;
import ch.bt.model.searchtoken.SearchTokenListInts;
import ch.bt.rc.BestRangeCover;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.jetbrains.annotations.NotNull;
import org.openjdk.jmh.annotations.*;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;

public class Trapdoor {
    @State(Scope.Benchmark)
    public static class Constants {
        final String folder = "src/test/resources/benchmark";

        final String method = "trapdoor";
    }

    @State(Scope.Benchmark)
    public static class TokenPrinter {
        BufferedWriter fileWriter;
        CSVFormat csvFormat;
        CSVPrinter printer;

        public void printToCsv(
                final String type,
                final int dataSize,
                final int rangeSize,
                final List<String> token,
                @NotNull Trapdoor.Constants constants)
                throws IOException, SQLException, GeneralSecurityException {
            if (printer == null) {
                init(constants);
            }
            printer.printRecord(
                    type,
                    dataSize,
                    rangeSize,
                    token.stream().reduce((el1, el2) -> String.join(",", el1, el2)).orElse(""));
        }

        @Setup(Level.Trial)
        public void init(@NotNull Trapdoor.Constants constants)
                throws GeneralSecurityException, IOException, SQLException {
            final String file =
                    String.join(".", String.join("-", "encryptedIndex", constants.method), "csv");
            final var path = Paths.get(String.join("/", constants.folder, file));
            final var newFile = path.toFile();
            if (newFile.exists()) {
                csvFormat =
                        CSVFormat.DEFAULT
                                .builder()
                                .setHeader(
                                        "type",
                                        "table number",
                                        "data size",
                                        "label data",
                                        "label iv",
                                        "value1 data",
                                        "value1 iv")
                                .build();
            } else {
                csvFormat = CSVFormat.DEFAULT.builder().build();
            }
            fileWriter =
                    Files.newBufferedWriter(
                            path, StandardOpenOption.APPEND, StandardOpenOption.CREATE);
            printer = new CSVPrinter(fileWriter, csvFormat);
        }

        @TearDown(Level.Trial)
        public void tearDown() throws IOException {
            printer.close();
        }
    }

    @State(Scope.Benchmark)
    public static class Parameters {
        @Param("0")
        int numberOfDataSamples;

        @Param("0")
        int rangeSize;

        @Param("baseline")
        String type;

        RangeBRCScheme rangeBRCScheme;
        Vertex root;

        @Setup(Level.Trial)
        public void init() throws GeneralSecurityException, IOException, SQLException {
            System.out.println();
            System.out.println("INITIALIZE BENCHMARK: EXTRACT ROOT");
            System.out.println("------------------------------------------------------");

            Security.addProvider(new BouncyCastleFipsProvider());

            root = BenchmarkUtils.readRoot(numberOfDataSamples, type);

            final int securityParameter = 256;
            final var emm = new BasicEMM(securityParameter);
            rangeBRCScheme = new RangeBRCScheme(securityParameter, emm, new BestRangeCover(), root);

            System.out.println();
            System.out.println("Init done.");
        }
    }

    @State(Scope.Benchmark)
    public static class SampleFrom {

        CustomRange range;

        List<SearchToken> token;

        @Setup(Level.Iteration)
        public void init(@NotNull Parameters parameters) {
            final int from =
                    (int)
                                    (Math.random()
                                            * (parameters.root.range().getMaximum()
                                                    - parameters.rangeSize))
                            + parameters.root.range().getMinimum();
            range = new CustomRange(from, from + parameters.rangeSize - 1);
            System.out.println();
            System.out.println(
                    "Running trapdoor for range ["
                            + from
                            + ", "
                            + (from + parameters.rangeSize - 1)
                            + "].");
        }

        @TearDown(Level.Iteration)
        public void tearDown(
                @NotNull TokenPrinter printer,
                @NotNull Trapdoor.Constants constants,
                @NotNull Parameters parameters)
                throws SQLException, GeneralSecurityException, IOException {
            System.out.println();
            System.out.println("End of iteration...");
            final var stringToken =
                    switch (parameters.type) {
                        case "volumeHiding" -> token.stream()
                                .map(SearchTokenListInts.class::cast)
                                .map(SearchTokenListInts::getSearchTokenList)
                                .map(
                                        el ->
                                                el.stream()
                                                        .map(String::valueOf)
                                                        .reduce(
                                                                (el1, el2) ->
                                                                        String.join(",", el1, el2)))
                                .map(s -> "<" + s + ">")
                                .toList();
                        default -> token.stream()
                                .map(SearchTokenBytes.class::cast)
                                .map(SearchTokenBytes::token)
                                .map(Arrays::toString)
                                .toList();
                    };
            printer.printToCsv(
                    parameters.type,
                    parameters.numberOfDataSamples,
                    parameters.rangeSize,
                    stringToken,
                    constants);
        }
    }

    @Benchmark
    public List<SearchToken> trapdoor(
            @NotNull Parameters parameters, @NotNull SampleFrom sampleFrom) {
        sampleFrom.token = parameters.rangeBRCScheme.trapdoor(sampleFrom.range);
        return sampleFrom.token;
    }
}
