package ch.bt.model.searchtoken;

import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * This record encapsulates a search token as a pair (integer, byte array)
 *
 * @param token the integer token
 * @param token2 the token as a byte array
 * @author Janet Greutmann
 */
public record SearchTokenIntBytes(int token, byte[] token2) implements SearchToken {
    /**
     * Generated method
     *
     * @return the data of this in string format
     */
    @Override
    public String toString() {
        return new ToStringBuilder(this).append("token", token).append("token2", token2).toString();
    }
}
