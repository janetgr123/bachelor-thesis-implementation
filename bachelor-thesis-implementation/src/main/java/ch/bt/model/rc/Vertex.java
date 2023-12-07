package ch.bt.model.rc;

import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.jetbrains.annotations.NotNull;

public class Vertex implements Comparable<Vertex> {
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        Vertex vertex = (Vertex) o;

        return new EqualsBuilder().append(id, vertex.id).append(range, vertex.range).isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(id).append(range).toHashCode();
    }

    @Override
    public int compareTo(@NotNull Vertex vertex) {
        return new CompareToBuilder()
                .append(id, vertex.id)
                .append(range, vertex.range)
                .toComparison();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("id", id)
                .append("range", range)
                .toString();
    }
}
