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
            System.out.println("INITIALIZE BENCHMARK: EXTRACT ENCRYPTED INDEX AND SEARCH TOKENS");
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

        CustomRange range;

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
    }

    @Benchmark
    public Set<Ciphertext> search(@NotNull Parameters parameters, @NotNull SampleFrom sampleFrom) {
        return parameters.rangeBRCScheme.search(null, null);
    }
}
