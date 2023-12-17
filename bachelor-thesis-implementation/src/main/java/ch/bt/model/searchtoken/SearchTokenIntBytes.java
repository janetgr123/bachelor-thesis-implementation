package ch.bt.model.searchtoken;

import org.apache.commons.lang3.builder.ToStringBuilder;

public record SearchTokenIntBytes(int token, byte[] token2) implements SearchToken {
    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("token", token)
                .append("token2", token2)
                .toString();
    }
}
