package ch.bt.model.searchtoken;

import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * This class encapsulates a search token as a pair of integers
 *
 * @author Janet Greutmann
 */
public class SearchTokenInts {
    /** the first token */
    private final int token1;

    /** the second token */
    private final int token2;

    public SearchTokenInts(final int token1, final int token2) {
        this.token1 = token1;
        this.token2 = token2;
    }

    /**
     * Generated method
     *
     * @return the data of this in string format
     */
    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("token1", token1)
                .append("token2", token2)
                .toString();
    }

    /**
     * Getter for one of the token
     *
     * @param number the number of the token (@required 1 or 2)
     * @return token1 is number is 1, token2 otherwise
     */
    public int getToken(final int number) {
        return number == 1 ? token1 : token2;
    }
}
