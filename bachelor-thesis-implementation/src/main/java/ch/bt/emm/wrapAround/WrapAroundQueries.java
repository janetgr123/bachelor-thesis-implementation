package ch.bt.emm.wrapAround;

import ch.bt.model.BiasedCoin;
import ch.bt.model.rc.CustomRange;

import java.util.*;

/**
 * This class implements the wrap around queries * technique from <a
 * href="https://doi.org/10.1007/978-3-030-30215-3_12">Markatou et al.</a>
 *
 * @author Janet Greutmann
 */
public class WrapAroundQueries {
    private final int n;
    private final int t;

    public WrapAroundQueries(final int n, final int t) {
        this.n = n;
        this.t = t;
    }

    public List<CustomRange> wrapAroundQueriesUpToSizeT(final CustomRange range) {
        final var coin = new BiasedCoin(n, t);
        final var normalQueries = new HashSet<CustomRange>();
        final var wrapAroundQueries = new HashSet<CustomRange>();
        for (int i = 1; i <= n; i++) {
            for (int j = 1; j <= i && i - j <= t; j++) {
                normalQueries.add(new CustomRange(j, i));
            }
        }
        for (int i = 1; i <= n; i++) {
            for (int j = 1; j < i && j + n - i <= t; j++) {
                wrapAroundQueries.add(new CustomRange(i, j));
            }
        }
        return generatePair(coin, range, normalQueries, wrapAroundQueries);
    }

    private List<CustomRange> generatePair(
            final BiasedCoin coin,
            final CustomRange range,
            final Set<CustomRange> normalQueries,
            final Set<CustomRange> wrapAroundQueries) {
        CustomRange next = range;
        // for correctness reasons range must be in pair
        final var pair = new ArrayList<>(createShuffledSingletons(next));
        if (coin.flipCoin() == 1) {
            next = new ArrayList<>(normalQueries).get(drawRandomItemFrom(normalQueries));
        } else {
            next = new ArrayList<>(wrapAroundQueries).get(drawRandomItemFrom(wrapAroundQueries));
        }
        pair.addAll(createShuffledSingletons(next));
        Collections.shuffle(pair);
        return pair;
    }

    private int drawRandomItemFrom(final Set<CustomRange> set) {
        return (int) (Math.random() * set.size());
    }

    private List<CustomRange> createShuffledSingletons(final CustomRange next) {
        final var singletons = new ArrayList<CustomRange>();
        final int start = next.getMinimum();
        final int end = next.getMaximum();
        for (int j = start; j <= end; j++) {
            singletons.add(new CustomRange(j, j));
        }
        Collections.shuffle(singletons);
        return singletons;
    }
}
