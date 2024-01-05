package ch.bt.model.multimap;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

import java.util.Arrays;

/**
 * This record encapsulates a label of a multimap
 *
 * @param label the label as a byte array
 * @author Janet Greutmann
 */
public record Label(byte[] label) implements Comparable<Label> {
    /**
     * Generated method
     *
     * @param other the label that should be compared to this
     * @return negative number if this &lt; other, 0 for equality and positive number if this &gt; other
     */
    @Override
    public int compareTo(Label other) {
        return Arrays.compare(label, other.label);
    }

    /**
     * Generated method
     *
     * @return the data of this in string format
     */
    @Override
    public String toString() {
        return new ToStringBuilder(this).append("label", label).toString();
    }

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

        Label label1 = (Label) o;

        return new EqualsBuilder().append(label, label1.label).isEquals();
    }

    /**
     * Generated method
     *
     * @return the hash code of this
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(label).toHashCode();
    }

    /**
     * Getter for the label as a byte array
     *
     * @return the label as a byte array
     */
    public byte[] label() {
        return label;
    }
}
