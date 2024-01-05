package ch.bt.model.multimap;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * This class encapsulates a pair (label, number of values associated with this label)
 *
 * @author Janet Greutmann
 */
public class PairLabelNumberValues extends Ciphertext {
    /** the label */
    private final Label label;

    /** the number of values associated with this label */
    private final int numberOfValues;

    public PairLabelNumberValues(Label label, int numberOfValues) {
        this.label = label;
        this.numberOfValues = numberOfValues;
    }

    /**
     * Generated method
     *
     * @return the data of this in string format
     */
    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("label", label)
                .append("numberOfValues", numberOfValues)
                .toString();
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

        PairLabelNumberValues that = (PairLabelNumberValues) o;

        return new EqualsBuilder()
                .append(numberOfValues, that.numberOfValues)
                .append(label, that.label)
                .isEquals();
    }

    /**
     * Generated method
     *
     * @return the hash code of this
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(label).append(numberOfValues).toHashCode();
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
     * Getter for the number of values
     *
     * @return the number of values
     */
    public int numberOfValues() {
        return numberOfValues;
    }
}
