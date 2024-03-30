package ch.bt.benchmark;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import java.io.IOException;
import java.security.Security;
import java.sql.SQLException;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.IntStream;

/**
 * This class runs the benchmarks.
 *
 * @author Janet Greutmann
 */
public class BenchmarkRunner {
    private static final Logger logger = Logger.getLogger(BenchmarkRunner.class.getName());

    static {
        Handler handlerObj = new ConsoleHandler();
        handlerObj.setLevel(Level.ALL);
        logger.addHandler(handlerObj);
        logger.setLevel(Level.ALL);
        logger.setUseParentHandlers(false);
    }

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

        logger.info("STARTING BENCHMARKS");
        IntStream.iterate(
                        BenchmarkSettings.MAX_NUMBER_OF_DATA_SAMPLES,
                        i -> i <= BenchmarkSettings.MAX_NUMBER_OF_DATA_SAMPLES,
                        i -> i * 2)
                .forEach(
                        dataSize -> {
                            BenchmarkUtils.setMultimapAndRootForDataSize(dataSize, dataSet);
                            if (twoRoundEMMs == 0) {
                                if (par == 0) {
                                    BenchmarkUtils.runBenchmarkForRangeScheme(emms, dataSize, k);
                                } else {
                                    BenchmarkUtils.runBenchmarkForParallelRangeScheme(
                                            emms, dataSize, k);
                                }
                            } else {
                                if (par == 0) {
                                    BenchmarkUtils.runBenchmarkForDPRangeScheme(dataSize, k);
                                } else {
                                    BenchmarkUtils.runBenchmarkForParallelDPRangeScheme(
                                            dataSize, k);
                                }
                            }
                        });
        logger.info("DONE");
        logger.info(
                "Experiment time: " + ((System.currentTimeMillis() - start) / 1000) + " seconds.");
    }
}
