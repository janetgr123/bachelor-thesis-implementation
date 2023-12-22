package ch.bt.model.searchtoken;

import org.apache.commons.lang3.builder.ToStringBuilder;

public record SearchTokenBytes(byte[] token) implements SearchToken {
    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("token", token)
                .toString();
    }
}
