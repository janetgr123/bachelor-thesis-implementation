package ch.bt.model.multimap;

import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * This record encapsulates a plaintext
 *
 * @param data the plaintext data as a byte array
 * @author Janet Greutmann
 */
public record Plaintext(byte[] data) implements Comparable<Plaintext> {
    /**
     * Generated method
     *
     * @param o the object that should be tested for equality to this
     * @return true is the objects are equal, false otherwise
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        Plaintext plaintext = (Plaintext) o;

        return new EqualsBuilder().append(data, plaintext.data).isEquals();
    }

    /**
     * Generated method
     *
     * @param plaintext the plaintext that should be compared to this
     * @return negative number if this &lt; plaintext, 0 for equality and positive number if this
     *     &gt; plaintext
     */
    @Override
    public int compareTo(Plaintext plaintext) {
        return new CompareToBuilder().append(this.data, plaintext.data).toComparison();
    }

    /**
     * Generated method
     *
     * @return the hash code of this
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(data).toHashCode();
    }

    /**
     * Generated method
     *
     * @return the data of this in string format
     */
    @Override
    public String toString() {
        return new ToStringBuilder(this).append("data", data).toString();
    }
}
