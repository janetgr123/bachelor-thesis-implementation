package ch.bt.rc;

import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;

import java.util.*;
import java.util.function.Predicate;

public class BestRangeCover implements RangeCoveringAlgorithm {
    List<Vertex> explored;

    public BestRangeCover() {
        explored = new ArrayList<>();
    }

    @Override
    public Set<Vertex> getRangeCover(final CustomRange q, final Vertex v) {
        final var cover = getRangeCover(q, v, new HashSet<>());
        explored = new ArrayList<>();
        return cover;
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
                        RangeCoverUtils.getSuccessorsOf(v).stream()
                                .filter(Predicate.not(explored::contains))
                                .toList();
                successorsOfV.forEach(w -> rangeCover.addAll(getRangeCover(q, w)));
            }
        }
        return rangeCover;
    }
}
