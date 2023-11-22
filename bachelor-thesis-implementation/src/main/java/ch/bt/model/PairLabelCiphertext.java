package ch.bt.model;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

public class PairLabelCiphertext extends Ciphertext {
    private final CiphertextWithIV label;
    private final CiphertextWithIV value;

    public PairLabelCiphertext(CiphertextWithIV label, CiphertextWithIV value) {
        this.label = label;
        this.value = value;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("label", label).append("value", value).toString();
    }

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

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(label).append(value).toHashCode();
    }

    public CiphertextWithIV label() {
        return label;
    }

    public CiphertextWithIV value() {
        return value;
    }
}