package ch.bt.model;

public class SearchTokenBytes implements SearchToken {
    private final byte[] token;

    public SearchTokenBytes(final byte[] token) {
        this.token = token;
    }

    public byte[] getToken() {
        return token;
    }
}
