package ch.bt.model;

public record SearchTokenIntBytes(int token, byte[] token2) implements SearchToken {
}
