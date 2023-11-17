package ch.bt.model;


public class Vertex {
    final String id;
    final CustomRange range;

    public Vertex(final String id, final CustomRange range) {
        this.id = id;
        this.range = range;
    }

    public String id() {
        return id;
    }

    public CustomRange range() {
        return range;
    }
}
