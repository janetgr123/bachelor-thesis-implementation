package ch.bt.model;

import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

public record Plaintext(byte[] data) implements Comparable<Plaintext> {
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        Plaintext plaintext = (Plaintext) o;

        return new EqualsBuilder().append(data, plaintext.data).isEquals();
    }

    @Override
    public int compareTo(Plaintext plaintext) {
        return new CompareToBuilder().append(this.data, plaintext.data).toComparison();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(data).toHashCode();
    }
}
