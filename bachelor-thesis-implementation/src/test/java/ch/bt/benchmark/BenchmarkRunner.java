package ch.bt.benchmark;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import java.io.IOException;
import java.security.Security;
import java.sql.SQLException;
import java.util.stream.IntStream;

/**
 * This class runs the benchmarks.
 *
 * @author Janet Greutmann
 */
public class BenchmarkRunner {

    static {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    public static void main(String[] args) throws SQLException, IOException {
        final long start = System.currentTimeMillis();

        // command line args
        final var emmType = Integer.parseInt(args[0]);
        final var twoRoundEMMs = Integer.parseInt(args[1]);
        final var dataSet = Integer.parseInt(args[2]);

        BenchmarkUtils.initializeData(dataSet);

        final var emms =
                switch (emmType) {
                    case 1 -> EMMS.vhEmms;
                    case 2 -> EMMS.vhOEmms;
                    default -> EMMS.basicEmms;
                };

        System.out.println("STARTING BENCHMARKS");
        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        IntStream.iterate(10, i -> i <= BenchmarkSettings.MAX_NUMBER_OF_DATA_SAMPLES, i -> i + 10)
                .forEach(
                        dataSize -> {
                            BenchmarkUtils.setMultimapAndRootForDataSize(dataSize, dataSet);
                            if (twoRoundEMMs == 0) {
                                BenchmarkUtils.runBenchmarkForRangeScheme(emms, dataSize);
                                BenchmarkUtils.runBenchmarkForParallelRangeScheme(emms, dataSize);
                            } else {
                                BenchmarkUtils.runBenchmarkForDPRangeScheme(dataSize);
                                BenchmarkUtils.runBenchmarkForParallelDPRangeScheme(dataSize);
                            }
                        });

        System.out.println();
        System.out.println("DONE");
        System.out.println(
                "Experiment time: " + ((System.currentTimeMillis() - start) / 1000) + " seconds.");
    }
}
