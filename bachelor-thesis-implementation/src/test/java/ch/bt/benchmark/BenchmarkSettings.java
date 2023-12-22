package ch.bt.benchmark;

public class BenchmarkSettings {
    public static final int NUMBER_OF_QUERIES =
            2; // number of queries for fixed parameters (e.g. data size, range size)
    public static final int WARM_UPS = 1; // number of warm-up iterations per benchmark run
    public static final String FOLDER = "src/test/resources/benchmark";
    public static final int FORKS =
            1; // we use only one JVM and neglect the influence of the random JVM instance
    public static final int MAX_NUMBER_OF_DATA_SAMPLES = 100;
}
