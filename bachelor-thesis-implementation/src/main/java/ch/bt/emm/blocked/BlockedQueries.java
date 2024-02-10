package ch.bt.emm.blocked;

import ch.bt.model.rc.CustomRange;

/**
 * This class implements the blocked queries * technique from <a *
 * href="https://doi.org/10.1007/978-3-030-30215-3_12">Markatou et al.</a>
 *
 * @author Janet Greutmann
 */
public class BlockedQueries {
    public static CustomRange blockedQuery(final CustomRange range, final int k) {
        final int start = k * ((int) Math.floor(range.getMinimum() / ((double) k)));
        final int end = k * ((int) Math.ceil((range.getMaximum() + 1) / ((double) k))) - 1;
        return new CustomRange(start, end);
    }
}
