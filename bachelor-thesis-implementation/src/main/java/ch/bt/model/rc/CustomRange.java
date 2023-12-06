package ch.bt.model.rc;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.ArrayList;
import java.util.stream.Stream;

public class CustomRange {

    private static final CustomRange EMPTY_RANGE = new CustomRange(0, -1);
    private final int from;
    private final int to;

    public CustomRange(final int from, final int to) {
        this.from = from;
        this.to = to;
    }

    public int getMinimum() {
        return from;
    }

    public int getMaximum() {
        return to;
    }

    public boolean isEmpty() {
        return from > to;
    }

    public boolean contains(final int element) {
        return (from <= element) && (element <= to);
    }

    public boolean containsRange(final CustomRange range) {
        return (from <= range.getMinimum()) && (range.getMaximum() <= to);
    }

    public boolean disjunct(final CustomRange range) {
        return (to < range.getMinimum()) || (range.getMaximum() < from);
    }

    public int size() {
        if (!isEmpty()) {
            return to - from + 1;
        }
        return 0;
    }

    public CustomRange intersectionWith(final CustomRange range) {
        if (disjunct(range)) {
            return EMPTY_RANGE;
        }
        if (this.containsRange(range)) {
            return range;
        } else if (range.containsRange(this)) {
            return this;
        }
        return new CustomRange(
                Math.max(from, range.getMinimum()), Math.min(to, range.getMaximum()));
    }

    public Stream<Integer> getStream() {
        final var values = new ArrayList<Integer>();
        for (int i = from; i <= to; i++) {
            values.add(i);
        }
        return values.stream();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        CustomRange that = (CustomRange) o;

        return new EqualsBuilder().append(from, that.from).append(to, that.to).isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(from).append(to).toHashCode();
    }
}
