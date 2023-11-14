package ch.bt.model;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.Arrays;

public class Label implements Comparable<Label> {
    private final byte[] label;

    public Label(final byte[] label) {
        this.label = label;
    }

    public byte[] getLabel() {
        return this.label;
    }

    @Override
    public int compareTo(Label other) {
        return Arrays.compare(label, other.label);
    }

    @Override
    public String toString() {
        return new org.apache.commons.lang3.builder.ToStringBuilder(this)
                .append("label", label)
                .toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        Label label1 = (Label) o;

        return new EqualsBuilder().append(label, label1.label).isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(label).toHashCode();
    }
}
