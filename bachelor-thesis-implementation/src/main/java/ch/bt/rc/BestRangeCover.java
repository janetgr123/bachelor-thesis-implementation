package ch.bt.rc;

import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;

import java.util.*;
import java.util.function.Predicate;

/**
 * This class implements the BRC range covering algorithm based on <a
 * href="https://doi.org/10.14778/3574245.3574247">Falzon et al.</a>
 *
 * @author Janet Greutmann
 */
public class BestRangeCover implements RangeCoveringAlgorithm {
    /** the list of nodes that have already been explored by the algorithm */
    List<Vertex> explored;

    public BestRangeCover() {
        explored = new ArrayList<>();
    }

    /**
     * This method wraps the recursive getRangeCover(q, v, rangeCover)
     *
     * @param q the range query
     * @param v the starting vertex
     * @return the set of vertices that covers the range q
     */
    @Override
    public Set<Vertex> getRangeCover(final CustomRange q, final Vertex v) {
        final var cover = getRangeCover(q, v, new HashSet<>());
        explored = new ArrayList<>();
        return cover;
    }

    /**
     * @param q the range query
     * @param v the current vertex
     * @param rangeCover the current range cover as a set of vertices
     * @return the set of vertices that covers the already explored part of the graph. The vertices
     *     of the graph are calculated during runtime.
     */
    private Set<Vertex> getRangeCover(
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
