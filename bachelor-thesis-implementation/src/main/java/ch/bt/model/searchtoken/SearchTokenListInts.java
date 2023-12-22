package ch.bt.model.searchtoken;

import org.apache.commons.lang3.builder.ToStringBuilder;

import java.util.List;

public class SearchTokenListInts implements SearchToken {
    private final List<SearchTokenInts> token;

    public SearchTokenListInts(final List<SearchTokenInts> token) {
        this.token = token;
    }

    public List<SearchTokenInts> getSearchTokenList() {
        return token;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("token", token)
                .toString();
    }
}
