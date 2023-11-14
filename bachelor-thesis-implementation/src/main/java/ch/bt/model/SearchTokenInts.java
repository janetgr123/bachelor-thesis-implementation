package ch.bt.model;

public class SearchTokenInts {
    private final int token1;
    private final int token2;

    public SearchTokenInts(final int token1, final int token2) {
        this.token1 = token1;
        this.token2 = token2;
    }

    public int getToken(final int number) {
        return number == 1 ? token1 : token2;
    }

}
