package ch.bt.rc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;

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
            RangeCoverUtils.addVerticesAndEdgesForLevel(vertices, graph, i);
        }

        final var rangeQuery = new CustomRange(2, 6);
        final var rangeCover =
                brc.getRangeCover(graph, rangeQuery, RangeCoverUtils.getVertex(graph, "07"));
        assertEquals(3, rangeCover.size());

        final var expectedCover = new HashSet<Vertex>();
        expectedCover.add(RangeCoverUtils.getVertex(graph, "23"));
        expectedCover.add(RangeCoverUtils.getVertex(graph, "45"));
        expectedCover.add(RangeCoverUtils.getVertex(graph, "66"));
        assertEquals(expectedCover, rangeCover);
    }
}
