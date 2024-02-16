package ch.bt.benchmark;

/**
 * This class encapsulates the benchmark settings.
 *
 * @author Janet Greutmann
 */
public class BenchmarkSettings {
    public static final int NUMBER_OF_QUERIES =
            100; // number of queries for fixed parameters (e.g. data size, range size)
    public static final int WARM_UPS = 2; // number of warm-up iterations per benchmark run
    public static final int MAX_NUMBER_OF_DATA_SAMPLES = 16384; // 2^14
    public static final int DOMAIN_SIZE = 16384; // 2^14
    public static final int ITERATIONS_BUILD_INDEX = 5;
}
