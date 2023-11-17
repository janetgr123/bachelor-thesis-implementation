package ch.bt.rc;

import ch.bt.model.CustomRange;
import ch.bt.model.Vertex;

import org.jgrapht.Graph;
import org.jgrapht.Graphs;
import org.jgrapht.graph.DefaultEdge;

import java.util.*;
import java.util.function.Predicate;

public class BestRangeCover implements RangeCoveringAlgorithm {
    final List<Vertex> explored = new ArrayList<>();

    @Override
    public Set<Vertex> getRangeCover(
            final Graph<Vertex, DefaultEdge> graph, final CustomRange q, final Vertex v) {
        return getRangeCover(graph, q, v, new HashSet<>());
    }

    public Set<Vertex> getRangeCover(
            final Graph<Vertex, DefaultEdge> graph,
            final CustomRange q,
            final Vertex v,
            final Set<Vertex> rangeCover) {
        explored.add(v);
        if (q.containsRange(v.range())) {
            rangeCover.add(v);
        } else {
            if (!v.range().intersectionWith(q).isEmpty()) {
                final var successorsOfV =
                        Graphs.successorListOf(graph, v).stream()
                                .filter(Predicate.not(explored::contains))
                                .toList();
                successorsOfV.forEach(w -> rangeCover.addAll(getRangeCover(graph, q, w)));
            }
        }
        return rangeCover;
    }
}
