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
        final int emmType = Integer.parseInt(args[0]);
        final int twoRoundEMMs = Integer.parseInt(args[1]);
        final int dataSet = Integer.parseInt(args[2]);
        final double epsilon = Double.parseDouble(args[3]);
        final int truncationProbability = Integer.parseInt(args[4]);
        final int k = Integer.parseInt(args[5]);
        final int par = Integer.parseInt(args[6]);
        final int bq = Integer.parseInt(args[7]);
        final int wq = Integer.parseInt(args[8]);

        EMMSettings.setEPSILON(epsilon);
        EMMSettings.setTruncationProbability(truncationProbability);

        BenchmarkUtils.initializeData(dataSet);

        final var emms =
                switch (emmType) {
                    case 1 -> EMMS.vhEmms;
                    case 2 -> EMMS.vhOEmms;
                    case 3 -> EMMS.oneRoundEMMs;
                    case 4 -> EMMS.oneRoundEMM2s;
                    default -> EMMS.basicEmms;
                };

        System.out.println("STARTING BENCHMARKS");
        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        IntStream.iterate(2, i -> i <= BenchmarkSettings.MAX_NUMBER_OF_DATA_SAMPLES, i -> i * 2)
                .forEach(
                        dataSize -> {
                            BenchmarkUtils.setMultimapAndRootForDataSize(dataSize, dataSet);
                            if (twoRoundEMMs == 0) {
                                if (par == 0) {
                                    if (bq == 1) {
                                        final int error = Integer.parseInt(args[9]);
                                        BenchmarkUtils.runBenchmarkForRangeSchemeBQ(
                                                emms, dataSize, k, error);
                                    } else if (wq == 1) {
                                        BenchmarkUtils.runBenchmarkForRangeSchemeWQ(
                                                emms, dataSize, k, dataSize);
                                    } else {
                                        BenchmarkUtils.runBenchmarkForRangeScheme(
                                                emms, dataSize, k);
                                    }
                                } else {
                                    if (bq == 1 || wq == 1) {
                                        throw new IllegalArgumentException(
                                                "BQ and WQ not available for parallel range schemes.");
                                    }
                                    BenchmarkUtils.runBenchmarkForParallelRangeScheme(
                                            emms, dataSize, k);
                                }
                            } else {
                                if (bq == 1 || wq == 1) {
                                    throw new IllegalArgumentException(
                                            "BQ and WQ not available for two round range schemes.");
                                }
                                if (par == 0) {
                                    BenchmarkUtils.runBenchmarkForDPRangeScheme(dataSize, k);
                                } else {
                                    BenchmarkUtils.runBenchmarkForParallelDPRangeScheme(
                                            dataSize, k);
                                }
                            }
                        });
        System.out.println();
        System.out.println("DONE");
        System.out.println(
                "Experiment time: " + ((System.currentTimeMillis() - start) / 1000) + " seconds.");
    }
}
