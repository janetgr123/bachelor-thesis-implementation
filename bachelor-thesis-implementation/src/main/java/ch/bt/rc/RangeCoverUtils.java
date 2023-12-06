package ch.bt.rc;

import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;

import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;

import java.util.HashSet;
import java.util.Set;

public class RangeCoverUtils {
    public static void addVerticesAndEdgesForLevel(
            final Set<Vertex> vertices,
            Graph<Vertex, DefaultEdge> graph,
            final int level,
            final int n) {
        final int size = (int) Math.pow(2, level) - 1;
        for (int i = 0; i < n; i += 1 + size) {
            final var range = new CustomRange(i, i + size);
            final var targetVertices =
                    vertices.stream()
                            .filter(
                                    el ->
                                            range.containsRange(el.range())
                                                    && (el.range().size()
                                                            == ((int) Math.pow(2, level - 1))))
                            .toList();
            final var sourceVertex =
                    new Vertex(
                            String.join("-", String.valueOf(i), String.valueOf(i + size)), range);
            vertices.add(sourceVertex);
            graph.addVertex(sourceVertex);
            targetVertices.forEach(
                    targetVertex -> graph.addEdge(sourceVertex, targetVertex, new DefaultEdge()));
        }
    }

    public static Vertex getVertex(final Graph<Vertex, DefaultEdge> graph, final String id) {
        final var vertex = graph.vertexSet().stream().filter(el -> el.id().equals(id)).findAny();
        return vertex.orElse(null);
    }

    public static Set<Vertex> getSuccessorsOf(final Vertex v) {
        if (v.range().size() == 1) {
            return new HashSet<>();
        }
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
