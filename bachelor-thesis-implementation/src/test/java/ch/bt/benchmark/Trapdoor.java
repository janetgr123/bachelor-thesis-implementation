package ch.bt.benchmark;

import ch.bt.TestUtils;
import ch.bt.emm.EMM;
import ch.bt.emm.basic.BasicEMM;
import ch.bt.emm.volumeHiding.VolumeHidingEMM;
import ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised;
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
                final int from,
                final List<String> token,
                @NotNull Trapdoor.Constants constants)
                throws IOException, SQLException, GeneralSecurityException {
            if (printer == null) {
                init(constants);
            }
            final var tokenString =
                    token.stream().reduce((el1, el2) -> String.join(",", el1, el2)).orElse("");
            printer.printRecord(type, dataSize, rangeSize, from, tokenString);
        }

        @Setup(Level.Trial)
        public void init(@NotNull Constants constants)
                throws GeneralSecurityException, IOException, SQLException {
            final String file =
                    String.join(".", String.join("-", "token", constants.method), "csv");
            final var path = Paths.get(String.join("/", constants.folder, file));
            final var newFile = path.toFile();
            if (newFile.exists()) {
                csvFormat =
                        CSVFormat.DEFAULT
                                .builder()
                                .setHeader("type", "data size", "range size", "from", "token")
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

        Vertex root;
        RangeBRCScheme rangeBRCScheme;
        EMM emm;

        @Param("baseline")
        String type;

        int securityParameter;

        @Setup(Level.Trial)
        public void init() throws GeneralSecurityException, IOException, SQLException {
            System.out.println();
            System.out.println("INITIALIZE BENCHMARK: EXTRACT ROOT, MULTIMAP AND SCHEME PARAMS");
            System.out.println("------------------------------------------------------");

            Security.addProvider(new BouncyCastleFipsProvider());

            securityParameter = 256;

            root = BenchmarkUtils.readRoot(numberOfDataSamples, type);

            final var paramsOfMultimap = BenchmarkUtils.readSizes(numberOfDataSamples, type);
            final var keys = BenchmarkUtils.getKeys(numberOfDataSamples, type);
            final var numberOfValues = paramsOfMultimap.get(1);
            final var maxNumberOfValues = paramsOfMultimap.get(0);
            final var prfKey = keys.get(0);
            final var aesKey = keys.get(1);

            System.out.println(
                    "params: "
                            + numberOfValues
                            + ", "
                            + maxNumberOfValues
                            + ", "
                            + Arrays.toString(prfKey.getEncoded())
                            + ", "
                            + Arrays.toString(aesKey.getEncoded()));

            emm =
                    switch (type) {
                        case "volumeHiding" -> new VolumeHidingEMM(
                                TestUtils.ALPHA, maxNumberOfValues, numberOfValues, prfKey, aesKey);
                        case "volumeHidingOpt" -> new VolumeHidingEMMOptimised(
                                TestUtils.ALPHA, maxNumberOfValues, numberOfValues, prfKey, aesKey);
                        default -> new BasicEMM(prfKey, aesKey);
                    };

            System.out.println();
            System.out.println(
                    "Trial with Dataset Size "
                            + numberOfDataSamples
                            + " and Range Scheme Type "
                            + emm.getClass());

            rangeBRCScheme = new RangeBRCScheme(securityParameter, emm, new BestRangeCover(), root);

            System.out.println();
            System.out.println("Init done.");
        }
    }

    @State(Scope.Benchmark)
    public static class SampleFrom {
        CustomRange range;
        List<SearchToken> token;

        @Param("0")
        int rangeSize;

        @Setup(Level.Iteration)
        public void init(@NotNull Parameters parameters)
                throws GeneralSecurityException, IOException {

            final int from =
                    (int) (Math.random() * (parameters.root.range().getMaximum() - rangeSize))
                            + parameters.root.range().getMinimum();
            range = new CustomRange(from, from + rangeSize - 1);

            System.out.println();
            System.out.println(
                    "Running trapdoor for range ["
                            + range.getMinimum()
                            + ", "
                            + range.getMaximum()
                            + "].");
        }

        @TearDown(Level.Iteration)
        public void tearDown(
                @NotNull TokenPrinter printer,
                @NotNull Constants constants,
                @NotNull Parameters parameters)
                throws SQLException, GeneralSecurityException, IOException {
            System.out.println();
            System.out.println("End of iteration...");
            System.out.println("Token before saving: " + token.toString());

            final var stringToken =
                    switch (parameters.type) {
                        case "volumeHiding" -> token.stream()
                                .map(SearchTokenListInts.class::cast)
                                .map(SearchTokenListInts::getSearchTokenList)
                                .map(
                                        el ->
                                                el.stream()
                                                        .map(
                                                                i ->
                                                                        "("
                                                                                + i.getToken(1)
                                                                                + ","
                                                                                + i.getToken(2)
                                                                                + ")")
                                                        .reduce(
                                                                (el1, el2) ->
                                                                        String.join(",", el1, el2)))
                                .map(pair -> pair.orElse(null))
                                .toList();
                        default -> token.stream()
                                .map(SearchTokenBytes.class::cast)
                                .map(SearchTokenBytes::token)
                                .map(Arrays::toString)
                                .toList();
                    };

            System.out.println("String token: " + stringToken);
            printer.printToCsv(
                    parameters.type,
                    parameters.numberOfDataSamples,
                    rangeSize,
                    range.getMinimum(),
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
