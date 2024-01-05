package ch.bt.rc;

import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;

import java.util.Set;

/**
 * This interface generalizes a range covering algorithm.
 *
 * @author Janet Greutmann
 */
public interface RangeCoveringAlgorithm {
    /**
     * @param q the range query
     * @param v the starting vertex
     * @return the range cover of q as a set of vertices
     */
    Set<Vertex> getRangeCover(CustomRange q, Vertex v);
}
