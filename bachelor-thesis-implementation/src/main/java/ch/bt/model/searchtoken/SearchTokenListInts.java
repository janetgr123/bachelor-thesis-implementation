package ch.bt.model.searchtoken;

import org.apache.commons.lang3.builder.ToStringBuilder;

import java.util.List;

/**
 * This class encapsulates a search token as a list of integer pairs
 *
 * @author Janet Greutmann
 */
public class SearchTokenListInts implements SearchToken {
    /** the list of integer pairs */
    private final List<SearchTokenInts> token;

    public SearchTokenListInts(final List<SearchTokenInts> token) {
        this.token = token;
    }

    /**
     * Getter for the token list
     *
     * @return the token list
     */
    public List<SearchTokenInts> getSearchTokenList() {
        return token;
    }

    /**
     * Generated method
     *
     * @return the data of this in string format
     */
    @Override
    public String toString() {
        return new ToStringBuilder(this).append("token", token).toString();
    }
}
