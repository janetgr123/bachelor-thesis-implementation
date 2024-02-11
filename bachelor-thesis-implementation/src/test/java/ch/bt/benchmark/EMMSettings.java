package ch.bt.benchmark;

/**
 * This class encapsulates the EMM settings
 *
 * @author Janet Greutmann
 */
public class EMMSettings {
    public static final int SECURITY_PARAMETER = 256;
    public static final double ALPHA = 0.3;
    public static double EPSILON = 0.2;
    public static int TRUNCATION_PROBABILITY = 32;
    public static final double T =
            Math.ceil(
                    -Math.log(
                            Math.pow(
                                    2,
                                    -TRUNCATION_PROBABILITY
                                            - Math.log(BenchmarkSettings.DOMAIN_SIZE)
                                                    / Math.log(2))));

    public static void setEPSILON(final double epsilon) {
        EPSILON = epsilon;
    }

    public static void setTruncationProbability(final int t) {
        TRUNCATION_PROBABILITY = t;
    }
}
