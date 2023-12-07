package ch.bt.model.searchtoken;

import java.util.List;

public class SearchTokenListInts implements SearchToken {
    private final List<SearchTokenInts> token;

    public SearchTokenListInts(final List<SearchTokenInts> token) {
        this.token = token;
    }

    public List<SearchTokenInts> getSearchTokenList() {
        return token;
    }
}
