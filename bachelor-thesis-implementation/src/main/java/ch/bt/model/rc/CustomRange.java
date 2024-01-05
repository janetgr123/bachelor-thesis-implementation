package ch.bt.model.rc;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.ArrayList;
import java.util.stream.Stream;

/**
 * This class encapsulates an integer interval
 *
 * @author Janet Greutmann
 */
public class CustomRange {

    /** the empty range */
    private static final CustomRange EMPTY_RANGE = new CustomRange(0, -1);

    /** the left border of the interval */
    private final int from;

    /** the right border of the interval */
    private final int to;

    public CustomRange(final int from, final int to) {
        this.from = from;
        this.to = to;
    }

    /**
     * @return the smallest point in the interval
     */
    public int getMinimum() {
        return from;
    }

    /**
     * @return the greatest point in the interval
     */
    public int getMaximum() {
        return to;
    }

    /**
     * @return true if the interval is empty (empty is defined as from > to)
     */
    public boolean isEmpty() {
        return from > to;
    }

    /**
     * @param element an integer point
     * @return true if the element is in the interval
     */
    public boolean contains(final int element) {
        return (from <= element) && (element <= to);
    }

    /**
     * @param range an integer range
     * @return true if the integer range is contained in this range
     */
    public boolean containsRange(final CustomRange range) {
        return (from <= range.getMinimum()) && (range.getMaximum() <= to);
    }

    /**
     * @param range an integer range
     * @return true if the range and this are disjoint
     */
    public boolean disjoint(final CustomRange range) {
        return (to < range.getMinimum()) || (range.getMaximum() < from);
    }

    /**
     * @return the number of integer points contained in the interval
     */
    public int size() {
        if (!isEmpty()) {
            return to - from + 1;
        }
        return 0;
    }

    /**
     * @param range an integer range
     * @return the intersection of range and this
     */
    public CustomRange intersectionWith(final CustomRange range) {
        if (disjoint(range)) {
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

    /**
     * @return the integer points of the interval as an integer stream
     */
    public Stream<Integer> getStream() {
        final var values = new ArrayList<Integer>();
        for (int i = from; i <= to; i++) {
            values.add(i);
        }
        return values.stream();
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

        CustomRange that = (CustomRange) o;

        return new EqualsBuilder().append(from, that.from).append(to, that.to).isEquals();
    }

    /**
     * Generated method
     *
     * @return the hash code of this
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(from).append(to).toHashCode();
    }
}
