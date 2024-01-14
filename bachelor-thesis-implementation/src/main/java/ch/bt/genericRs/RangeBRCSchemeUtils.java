package ch.bt.genericRs;

import ch.bt.crypto.CastingHelpers;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.rc.Vertex;
import ch.bt.rc.RangeCoverUtils;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This class is a collection of static helper methods for {@link ch.bt.genericRs}
 *
 * @author Janet Greutmann
 */
public class RangeBRCSchemeUtils {
    /**
     * The data from the database is converted into a graph which is stored in a new multimap where
     * the labels are given by the vertices of the graph. This method calculates the graph during
     * runtime without storing it.
     *
     * @param v the vertex v
     * @param map the new multimap that corresponds to the graph
     * @param keys a list of the labels contained in the multimap that contains the data from the
     *     database
     * @param multiMap the multimap that contains the data from the multimap
     */
    public static void addVertex(
            final Vertex v,
            final Map<Label, Set<Plaintext>> map,
            final List<Integer> keys,
            final Map<Label, Set<Plaintext>> multiMap) {
        final var labels = keys.stream().filter(v.range()::contains).toList();
        final var values =
                labels.stream()
                        .map(CastingHelpers::fromIntToByteArray)
                        .map(Label::new)
                        .map(multiMap::get)
                        .flatMap(Collection::stream)
                        .collect(Collectors.toSet());
        // ignore empty entries (otherwise the table size of the cuckoo hashing is too small)
        if (!values.isEmpty()) {
            map.put(CastingHelpers.toLabel(v.range()), values);
        }
        final var successors = RangeCoverUtils.getSuccessorsOf(v);
        if (!successors.isEmpty()) {
            successors.forEach(el -> addVertex(el, map, keys, multiMap));
        }
    }
}
