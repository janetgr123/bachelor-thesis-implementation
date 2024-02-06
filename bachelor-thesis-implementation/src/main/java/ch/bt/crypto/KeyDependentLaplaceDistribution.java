package ch.bt.crypto;

import org.apache.commons.math3.distribution.LaplaceDistribution;

import java.util.HashMap;
import java.util.Map;

public class KeyDependentLaplaceDistribution {

    private final Map<byte[], Double> lookup = new HashMap<>();
    private final LaplaceDistribution laplaceDistribution;

    public KeyDependentLaplaceDistribution(final double mu, final double beta) {
        laplaceDistribution = new LaplaceDistribution(mu, beta);
    }

    public Double sample(final byte[] key) {
        if (lookup.containsKey(key)) {
            return lookup.get(key);
        }
        final var sample = laplaceDistribution.sample();
        lookup.put(key, sample);
        return sample;
    }
}
