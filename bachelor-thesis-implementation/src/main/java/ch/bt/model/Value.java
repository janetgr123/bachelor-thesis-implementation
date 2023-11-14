package ch.bt.model;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.Arrays;

public class Value implements Comparable<Value> {
    private final byte[] value;

    public Value(final byte[] value) {
        this.value = value;
    }

    public byte[] getValue() {
        return this.value;
    }

    @Override
    public int compareTo(Value other) {
        return Arrays.compare(value, other.value);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        Value value1 = (Value) o;

        return new EqualsBuilder().append(value, value1.value).isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(value).toHashCode();
    }
}
