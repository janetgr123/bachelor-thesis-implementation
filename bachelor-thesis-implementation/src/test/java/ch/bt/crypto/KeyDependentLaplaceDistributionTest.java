package ch.bt.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

public class KeyDependentLaplaceDistributionTest {
    @Test
    public void testDeterminism() {
        final var epsilon = 0.2;
        final var lap = new KeyDependentLaplaceDistribution(0, 2 / epsilon);
        final var key = new byte[] {1, 2, 3, 4};
        final var key2 = new byte[] {5, 6, 7, 8};
        final var sample1 = lap.sample(key);
        final var sample2 = lap.sample(key);
        final var sample3 = lap.sample(key2);
        assertEquals(sample1, sample2);
        assertNotEquals(sample1, sample3);
    }
}
