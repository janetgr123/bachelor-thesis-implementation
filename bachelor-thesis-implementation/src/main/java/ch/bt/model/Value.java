package ch.bt.model;

import java.util.Arrays;
import java.util.Comparator;

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
    public final boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof Value)) {
            return false;
        }
        final var other = (Value) o;
        return Arrays.equals(value, other.value);
    }
}
