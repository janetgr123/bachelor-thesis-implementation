package ch.bt.rc;

import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;

import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;

import java.util.Set;

public class RangeCoverUtils {
    public static void addVerticesAndEdgesForLevel(
            final Set<Vertex> vertices, Graph<Vertex, DefaultEdge> graph, final int level) {
        final int size = (int) Math.pow(2, level) - 1;
        for (int i = 0; i < 8; i += 1 + size) {
            final var range = new CustomRange(i, i + size);
            final var targetVertices =
                    vertices.stream()
                            .filter(
                                    el ->
                                            range.containsRange(el.range())
                                                    && el.range().size() > level - 1)
                            .toList();
            final var sourceVertex =
                    new Vertex(String.valueOf(i).concat(String.valueOf(i + size)), range);
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
}
