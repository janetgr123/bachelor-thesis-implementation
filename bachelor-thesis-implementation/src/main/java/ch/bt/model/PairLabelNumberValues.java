package ch.bt.model;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

public record PairLabelNumberValues(Label label, int numberOfValues) {

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("label", label)
                .append("numberOfValues", numberOfValues)
                .toString();
    }

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

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(label).append(numberOfValues).toHashCode();
    }
}
