package ch.bt.model.rc;

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
}
