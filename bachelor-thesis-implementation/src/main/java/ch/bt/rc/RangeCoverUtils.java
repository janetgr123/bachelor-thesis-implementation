package ch.bt.rc;

import ch.bt.crypto.CastingHelpers;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;

import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * This class is a collection of static helper methods for {@link ch.bt.rc}
 *
 * @author Janet Greutmann
 */
public class RangeCoverUtils {
    /**
     * This method is only for testing purposes. It adds vertices and edges to a test graph
     * levelwise.
     *
     * @param vertices a set of vertices
     * @param graph the graph
     * @param level the current level of the graph
     * @param n the number of vertices that are added at this level
     */
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

    /**
     * @param graph a graph
     * @param id the id of a vertex
     * @return the vertex with id id or null if the id is not contained in the graph
     */
    public static Vertex getVertex(final Graph<Vertex, DefaultEdge> graph, final String id) {
        final var vertex = graph.vertexSet().stream().filter(el -> el.id().equals(id)).findAny();
        return vertex.orElse(null);
    }

    /**
     * @param v the vertex v
     * @return the successors of v in the graph
     */
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

    /**
     * @param multiMap the multimap containing the data from the database
     * @return the root vertex of the graph that covers the whole range of the data in the multimap
     */
    public static Vertex getRoot(final Map<Label, Set<Plaintext>> multiMap) {
        final var keys =
                multiMap.keySet().stream()
                        .map(Label::label)
                        .map(CastingHelpers::fromByteArrayToInt)
                        .sorted()
                        .toList();
        final var size = keys.size();
        final var min = keys.get(0);
        final var max = keys.get(size - 1);
        final var root = new CustomRange(min, max);
        return new Vertex(String.join("-", String.valueOf(min), String.valueOf(max)), root);
    }
}
