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

public class RangeBRCSchemeUtils {
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
        map.put(CastingHelpers.toLabel(v.range()), values);
        final var successors = RangeCoverUtils.getSuccessorsOf(v);
        if (!successors.isEmpty()) {
            successors.forEach(el -> addVertex(el, map, keys, multiMap));
        }
    }
}
