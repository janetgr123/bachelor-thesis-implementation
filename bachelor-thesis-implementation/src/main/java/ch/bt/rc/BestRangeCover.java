package ch.bt.rc;

import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;

import java.util.*;
import java.util.function.Predicate;

public class BestRangeCover implements RangeCoveringAlgorithm {
    final List<Vertex> explored = new ArrayList<>();

    @Override
    public Set<Vertex> getRangeCover(final CustomRange q, final Vertex v) {
        return getRangeCover(q, v, new HashSet<>());
    }

    public Set<Vertex> getRangeCover(
            final CustomRange q, final Vertex v, final Set<Vertex> rangeCover) {
        if (q.isEmpty()) {
            return new HashSet<>();
        }
        explored.add(v);
        if (q.containsRange(v.range())) {
            rangeCover.add(v);
        } else {
            if (!v.range().intersectionWith(q).isEmpty()) {
                final var successorsOfV =
                        getSuccessorsOf(v).stream()
                                .filter(Predicate.not(explored::contains))
                                .toList();
                successorsOfV.forEach(w -> rangeCover.addAll(getRangeCover(q, w)));
            }
        }
        return rangeCover;
    }

    private Set<Vertex> getSuccessorsOf(final Vertex v) {
        final var rangeOfV = v.range();
        final var from = rangeOfV.getMinimum();
        final var to = rangeOfV.getMaximum();
        final var size = rangeOfV.size();
        final var middle = from + size / 2;
        final var leftInterval = new CustomRange(from, middle - 1);
        final var rightInterval = new CustomRange(middle, to);
        return Set.of(
                new Vertex(
                        String.join(
                                "-",
                                String.valueOf(leftInterval.getMinimum()),
                                String.valueOf(leftInterval.getMaximum())),
                        leftInterval),
                new Vertex(
                        String.join(
                                "-",
                                String.valueOf(rightInterval.getMinimum()),
                                String.valueOf(rightInterval.getMaximum())),
                        rightInterval));
    }
}
