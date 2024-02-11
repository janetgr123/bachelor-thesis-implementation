package ch.bt.model;

public class BiasedCoin {
    private final double probabilityZero;

    public BiasedCoin(final int n, final int t) {
        this.probabilityZero = 1 - (2.0 * n - t + 1) / (2 * n);
    }

    public int flipCoin() {
        final var result = Math.random();
        return result <= probabilityZero ? 0 : 1;
    }
}
