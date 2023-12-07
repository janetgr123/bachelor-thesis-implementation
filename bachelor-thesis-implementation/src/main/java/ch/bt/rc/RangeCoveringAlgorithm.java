package ch.bt.rc;

import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;

import java.util.Set;

public interface RangeCoveringAlgorithm {
    Set<Vertex> getRangeCover(CustomRange q, Vertex v);
}
