package ch.bt.model.multimap;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * This class encapsulates a pair of ciphertexts
 *
 * @author Janet Greutmann
 */
public class PairLabelCiphertext extends Ciphertext {
    /** the first ciphertext */
    private final CiphertextWithIV label;

    /** the second ciphertext */
    private final CiphertextWithIV value;

    public PairLabelCiphertext(CiphertextWithIV label, CiphertextWithIV value) {
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

        PairLabelCiphertext pairLabelValue = (PairLabelCiphertext) o;

        return new EqualsBuilder()
                .append(label, pairLabelValue.label)
                .append(value, pairLabelValue.value)
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
     * Getter for the first ciphertext
     *
     * @return the first ciphertext
     */
    public CiphertextWithIV label() {
        return label;
    }

    /**
     * Getter for the second ciphertext
     *
     * @return the second ciphertext
     */
    public CiphertextWithIV value() {
        return value;
    }
}
