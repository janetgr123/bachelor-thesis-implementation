package ch.bt.rc;

import ch.bt.model.CustomRange;
import ch.bt.model.Vertex;

import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;

import java.util.Set;

public interface RangeCoveringAlgorithm {
    Set<Vertex> getRangeCover(Graph<Vertex, DefaultEdge> graph, CustomRange q, Vertex v);
}
