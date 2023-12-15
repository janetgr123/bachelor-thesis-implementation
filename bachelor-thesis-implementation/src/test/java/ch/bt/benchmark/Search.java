package ch.bt.benchmark;

import ch.bt.emm.basic.BasicEMM;
import ch.bt.genericRs.RangeBRCScheme;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.multimap.Ciphertext;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.rc.BestRangeCover;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.jetbrains.annotations.NotNull;
import org.openjdk.jmh.annotations.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Search {

    @State(Scope.Benchmark)
    public static class Parameters {
        @Param("0")
        int numberOfDataSamples;

        @Param("0")
        int rangeSize;

        @Param("baseline")
        String type;

        RangeBRCScheme rangeBRCScheme;
        EncryptedIndex encryptedIndex;

        Vertex root;

        @Setup(Level.Trial)
        public void init() throws GeneralSecurityException, IOException, SQLException {
            System.out.println();
            System.out.println("INITIALIZE BENCHMARK: EXTRACT ENCRYPTED INDEX");
            System.out.println("------------------------------------------------------");

            Security.addProvider(new BouncyCastleFipsProvider());

            root = BenchmarkUtils.readRoot(numberOfDataSamples, type);

            final int securityParameter = 256;
            final var emm = new BasicEMM(securityParameter);
            rangeBRCScheme = new RangeBRCScheme(securityParameter, emm, new BestRangeCover(), root);
            encryptedIndex = BenchmarkUtils.extractIndex(numberOfDataSamples, type);

            System.out.println();
            System.out.println("Init done.");
        }
    }

    @State(Scope.Benchmark)
    public static class SampleFrom {

        Map<Integer, List<SearchToken>> fromToToken;
        CustomRange range;

        @Setup(Level.Iteration)
        public void init(@NotNull Parameters parameters) throws IOException {
            System.out.println();
            System.out.println("EXTRACTING SEARCH TOKEN");
            fromToToken =
                    BenchmarkUtils.extractToken(
                            parameters.numberOfDataSamples, parameters.type, parameters.rangeSize);
        }
    }

    @Benchmark
    public Set<Ciphertext> search(@NotNull Parameters parameters, @NotNull SampleFrom sampleFrom) {
        return parameters.rangeBRCScheme.search(null, null);
    }
}
