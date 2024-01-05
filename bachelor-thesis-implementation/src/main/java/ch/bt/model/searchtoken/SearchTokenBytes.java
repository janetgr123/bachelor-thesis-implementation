package ch.bt.model.searchtoken;

import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * This record encapsulates a search token as a byte array
 *
 * @param token the token as a byte array
 * @author Janet Greutmann
 */
public record SearchTokenBytes(byte[] token) implements SearchToken {
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
