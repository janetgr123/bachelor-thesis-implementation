package ch.bt.emm;

import ch.bt.crypto.SHA512Hash;
import ch.bt.model.*;

import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class VolumeHidingEMMUtilsTest {

    @Test
    public void testCuckooHashing(){
        final Map<PlaintextLabel, Set<PlaintextValue>> multimap = new HashMap<>();
        final var set1 = new HashSet<PlaintextValue>();
        set1.add(new PlaintextValue(new byte[2]));
        set1.add(new PlaintextValue(new byte[3]));
        multimap.put(new PlaintextLabel(new byte[1]), set1);
        final var set2 = new HashSet<PlaintextValue>();
        set2.add(new PlaintextValue(new byte[2]));
        set2.add(new PlaintextValue(new byte[4]));
        multimap.put(new PlaintextLabel(new byte[2]), set2);
        final var set3 = new HashSet<PlaintextValue>();
        set3.add(new PlaintextValue(new byte[2]));
        set3.add(new PlaintextValue(new byte[5]));
        multimap.put(new PlaintextLabel(new byte[3]), set3);
        final var table1 = new Pair[8];
        final var table2 = new Pair[8];
        final Stack<Pair> stash = new Stack<>();
        VolumeHidingEMMUtils.doCuckooHashingWithStash(8, table1, table2, multimap, stash, new SHA512Hash(), 4);
        assertEquals(1, stash.size());
        assertEquals(4, Arrays.stream(table1).filter(Objects::nonNull).count());
        assertEquals(1, Arrays.stream(table2).filter(Objects::nonNull).count());
    }
}
