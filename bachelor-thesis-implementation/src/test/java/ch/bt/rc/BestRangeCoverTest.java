package ch.bt.rc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;

import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.DirectedAcyclicGraph;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

/** Test examples from Demertzis et al. 2016 */
public class BestRangeCoverTest {

    private static Graph<Vertex, DefaultEdge> graph;
    private static Vertex root;

    @BeforeAll
    public static void init() {
        graph = new DirectedAcyclicGraph<>(DefaultEdge.class);
        final Set<Vertex> vertices = new HashSet<>();

        for (int i = 0; i < 4; i++) {
            RangeCoverUtils.addVerticesAndEdgesForLevel(vertices, graph, i, 8);
        }

        root = RangeCoverUtils.getVertex(graph, "0-7");
    }

    @Test
    public void testBRCWithInterval2_6() {
        final var rangeQuery = new CustomRange(2, 6);
        final var rangeCover = new BestRangeCover().getRangeCover(rangeQuery, root);
        assertEquals(3, rangeCover.size());

        final var expectedCover = new HashSet<Vertex>();
        expectedCover.add(RangeCoverUtils.getVertex(graph, "2-3"));
        expectedCover.add(RangeCoverUtils.getVertex(graph, "4-5"));
        expectedCover.add(RangeCoverUtils.getVertex(graph, "6-6"));
        assertEquals(expectedCover, rangeCover);
    }

    @Test
    public void testBRCWithInterval2_7() {
        final var rangeQuery = new CustomRange(2, 7);
        final var rangeCover = new BestRangeCover().getRangeCover(rangeQuery, root);
        assertEquals(2, rangeCover.size());

        final var expectedCover = new HashSet<Vertex>();
        expectedCover.add(RangeCoverUtils.getVertex(graph, "2-3"));
        expectedCover.add(RangeCoverUtils.getVertex(graph, "4-7"));
        assertEquals(expectedCover, rangeCover);
    }

    @Test
    public void testBRCWithInterval0_7() {
        final var rangeQuery = new CustomRange(0, 7);
        final var rangeCover = new BestRangeCover().getRangeCover(rangeQuery, root);
        assertEquals(1, rangeCover.size());

        final var expectedCover = new HashSet<Vertex>();
        expectedCover.add(RangeCoverUtils.getVertex(graph, "0-7"));
        assertEquals(expectedCover, rangeCover);
    }

    @Test
    public void testBRCWithIntervalEmpty() {
        final var rangeQuery = new CustomRange(1, 0);
        final var rangeCover = new BestRangeCover().getRangeCover(rangeQuery, root);
        assertEquals(0, rangeCover.size());

        final var expectedCover = new HashSet<Vertex>();
        assertEquals(expectedCover, rangeCover);
    }

    @Test
    public void testBRCWithIntervalSingle() {
        final var rangeQuery = new CustomRange(4, 4);
        final var rangeCover = new BestRangeCover().getRangeCover(rangeQuery, root);
        assertEquals(1, rangeCover.size());

        final var expectedCover = new HashSet<Vertex>();
        expectedCover.add(RangeCoverUtils.getVertex(graph, "4-4"));
        assertEquals(expectedCover, rangeCover);
    }
}
