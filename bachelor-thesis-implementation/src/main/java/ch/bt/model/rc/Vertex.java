package ch.bt.model.rc;

import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.jetbrains.annotations.NotNull;

/**
 * This record encapsulates a graph vertex
 *
 * @param id the id of the vertex
 * @param range the range that is covered by this vertex
 * @author Janet Greutmann
 */
public record Vertex(String id, CustomRange range) implements Comparable<Vertex> {
    /**
     * Generated method
     *
     * @param o the object that should be tested for equality to this
     * @return true is the objects are equal, false otherwise
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        Vertex vertex = (Vertex) o;

        return new EqualsBuilder().append(id, vertex.id).append(range, vertex.range).isEquals();
    }

    /**
     * Generated method
     *
     * @return the hash code of this
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(id).append(range).toHashCode();
    }

    /**
     * Generated method
     *
     * @param vertex the vertex that should be compared to this
     * @return negative number if this &lt; vertex, 0 for equality and positive number if this &gt;
     *     vertex
     */
    @Override
    public int compareTo(@NotNull Vertex vertex) {
        return new CompareToBuilder()
                .append(id, vertex.id)
                .append(range, vertex.range)
                .toComparison();
    }

    /**
     * Generated method
     *
     * @return the data of this in string format
     */
    @Override
    public String toString() {
        return new ToStringBuilder(this).append("id", id).append("range", range).toString();
    }
}
