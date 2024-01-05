package ch.bt.model.multimap;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * This class encapsulates a pair (label, value)
 *
 * @author Janet Greutmann
 */
public class PairLabelPlaintext extends Ciphertext {
    /** the label */
    private final Label label;

    /** the value */
    private final Plaintext value;

    public PairLabelPlaintext(Label label, Plaintext value) {
        this.label = label;
        this.value = value;
    }

    /**
     * Generated method
     *
     * @return the data of this in string format
     */
    @Override
    public String toString() {
        return new ToStringBuilder(this).append("label", label).append("value", value).toString();
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

        PairLabelPlaintext pairLabelPlaintext = (PairLabelPlaintext) o;

        return new EqualsBuilder()
                .append(label, pairLabelPlaintext.label)
                .append(value, pairLabelPlaintext.value)
                .isEquals();
    }

    /**
     * Generated method
     *
     * @return the hash code of this
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(label).append(value).toHashCode();
    }

    /**
     * Getter for the label
     *
     * @return the label
     */
    public Label label() {
        return label;
    }

    /**
     * Getter for the value
     *
     * @return the value
     */
    public Plaintext value() {
        return value;
    }
}
