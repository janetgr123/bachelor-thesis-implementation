package ch.bt.model.searchtoken;

import org.apache.commons.lang3.builder.ToStringBuilder;

public class SearchTokenInts {
    private final int token1;
    private final int token2;

    public SearchTokenInts(final int token1, final int token2) {
        this.token1 = token1;
        this.token2 = token2;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("token1", token1)
                .append("token2", token2)
                .toString();
    }

    public int getToken(final int number) {
        return number == 1 ? token1 : token2;
    }
}
