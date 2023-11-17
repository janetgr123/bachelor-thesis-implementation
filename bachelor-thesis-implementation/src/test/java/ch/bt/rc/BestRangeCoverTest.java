package ch.bt.rc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import ch.bt.model.CustomRange;
import ch.bt.model.Vertex;

import org.apache.logging.log4j.util.Strings;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.DirectedAcyclicGraph;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

public class BestRangeCoverTest {

    @Test
    public void testBRC() {
        final var brc = new BestRangeCover();
        final var graph = new DirectedAcyclicGraph<Vertex, DefaultEdge>(DefaultEdge.class);
        final Set<Vertex> vertices = new HashSet<>();

        for (int i = 0; i < 4; i++) {
            addVerticesAndEdgesForLevel(vertices, graph, i);
        }

        final var rangeQuery = new CustomRange(2, 6);
        final var rangeCover = brc.getRangeCover(graph, rangeQuery, getVertex(graph, "07"));
        assertEquals(3, rangeCover.size());

        final var expectedCover = new HashSet<Vertex>();
        expectedCover.add(getVertex(graph, "23"));
        expectedCover.add(getVertex(graph, "45"));
        expectedCover.add(getVertex(graph, "66"));
        assertEquals(expectedCover, rangeCover);
    }

    private void addVerticesAndEdgesForLevel(
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
                    new Vertex(Strings.concat(String.valueOf(i), String.valueOf(i + size)), range);
            vertices.add(sourceVertex);
            graph.addVertex(sourceVertex);
            targetVertices.forEach(
                    targetVertex -> graph.addEdge(sourceVertex, targetVertex, new DefaultEdge()));
        }
    }

    private Vertex getVertex(final Graph<Vertex, DefaultEdge> graph, final String id) {
        final var vertex = graph.vertexSet().stream().filter(el -> el.id().equals(id)).findAny();
        return vertex.orElse(null);
    }
}
