package ch.bt.benchmark;

import ch.bt.TestUtils;
import ch.bt.emm.EMM;
import ch.bt.emm.basic.BasicEMM;
import ch.bt.emm.volumeHiding.VolumeHidingEMM;
import ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised;
import ch.bt.genericRs.RangeBRCScheme;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.multimap.Ciphertext;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.bt.model.searchtoken.SearchToken;
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
import java.util.Map;
import java.util.Set;

public class Search {
    @State(Scope.Benchmark)
    public static class Constants {
        final String folder = "src/test/resources/benchmark";
        final String method = "search";
    }

    @State(Scope.Benchmark)
    public static class ResultPrinter {
        BufferedWriter fileWriter;
        CSVFormat csvFormat;
        CSVPrinter printer;

        public void printToCsv(
                final int col1,
                final int col2,
                final int col3,
                final int col4,
                final int col5,
                @NotNull Constants constants)
                throws IOException, SQLException, GeneralSecurityException {
            if (printer == null) {
                init(constants);
            }
            printer.printRecord(col1, col2, col3, col4, col5);
        }

        @Setup(Level.Trial)
        public void init(@NotNull Constants constants)
                throws GeneralSecurityException, IOException, SQLException {
            final String file =
                    String.join(".", String.join("-", "results", constants.method), "csv");
            final var path = Paths.get(String.join("/", constants.folder, file));
            final var newFile = path.toFile();
            if (newFile.exists()) {
                csvFormat = CSVFormat.DEFAULT.builder().build();
            } else {
                csvFormat =
                        CSVFormat.DEFAULT
                                .builder()
                                .setHeader(
                                        "range from",
                                        "range to",
                                        "token size",
                                        "response size",
                                        "dummy values")
                                .build();
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

        @Param("baseline")
        String type;

        EncryptedIndex encryptedIndex;
        EMM emm;
        RangeBRCScheme rangeBRCScheme;

        Vertex root;
        int securityParameter;

        @Setup(Level.Trial)
        public void init() throws GeneralSecurityException, IOException, SQLException {
            System.out.println();
            System.out.println(
                    "INITIALIZE BENCHMARK: EXTRACT ENCRYPTED INDEX, MULTIMAP AND SCHEME PARAMS");
            System.out.println("------------------------------------------------------");

            Security.addProvider(new BouncyCastleFipsProvider());
            securityParameter = 256;

            root = BenchmarkUtils.readRoot(numberOfDataSamples, type);
            encryptedIndex = BenchmarkUtils.extractIndex(numberOfDataSamples, type);

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
    public static class Token {
        @Param("0")
        int rangeSize;

        CustomRange range;
        List<SearchToken> token;

        Map<Integer, List<SearchToken>> fromToToken;
        Set<Ciphertext> ciphertexts;

        @Setup(Level.Iteration)
        public void init(@NotNull Parameters parameters)
                throws IOException, InterruptedException, GeneralSecurityException {
            fromToToken =
                    BenchmarkUtils.extractToken(
                            parameters.numberOfDataSamples, parameters.type, rangeSize);

            System.out.println();
            System.out.println("EXTRACTING SEARCH TOKEN FOR RANDOM BUT SEEN FROM");
            final var from = fromToToken.keySet().stream().findAny().orElse(-1);
            token = fromToToken.remove(from);
            range = new CustomRange(from, from + rangeSize - 1);
            System.out.println(
                    "Token for range [" + range.getMinimum() + ", " + range.getMaximum() + "].");
            System.out.println("TOKEN: " + token.toString());
        }

        @TearDown(Level.Iteration)
        public void tearDown(
                @NotNull ResultPrinter printer,
                @NotNull Constants constants,
                @NotNull Parameters parameters)
                throws SQLException, GeneralSecurityException, IOException {
            printer.printToCsv(
                    range.getMinimum(),
                    range.getMaximum(),
                    token.size(),
                    ciphertexts.size(),
                    parameters.emm.getPaddingOfResponses().stream().reduce(Integer::sum).orElse(0),
                    constants);
        }
    }

    @Benchmark
    public Set<Ciphertext> search(@NotNull Parameters parameters, @NotNull Token token) {
        token.ciphertexts =
                parameters.rangeBRCScheme.search(token.token, parameters.encryptedIndex);
        return token.ciphertexts;
    }
}
