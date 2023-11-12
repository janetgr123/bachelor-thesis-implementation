package ch.bt.model;

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
    public final boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof Label other)) {
            return false;
        }
        return Arrays.equals(label, other.label);
    }
}
