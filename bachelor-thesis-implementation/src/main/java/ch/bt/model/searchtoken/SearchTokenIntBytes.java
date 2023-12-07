package ch.bt.model.searchtoken;

public record SearchTokenIntBytes(int token, byte[] token2) implements SearchToken {
}
