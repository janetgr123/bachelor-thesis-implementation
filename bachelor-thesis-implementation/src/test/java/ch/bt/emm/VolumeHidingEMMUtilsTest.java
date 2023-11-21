package ch.bt.emm;

import static org.junit.jupiter.api.Assertions.assertEquals;

import ch.bt.TestConfigurations;
import ch.bt.model.*;
import ch.bt.model.Label;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.security.GeneralSecurityException;
import java.util.*;

@ExtendWith({TestConfigurations.class})
public class VolumeHidingEMMUtilsTest {

    private static final Map<Label, Set<Plaintext>> multimap = new HashMap<>();
    private static final Map<Label, Set<Plaintext>> multimap2 = new HashMap<>();

    @BeforeAll
    public static void init() {
        final var set1 = new HashSet<Plaintext>();
        final List<Plaintext> plaintexts = new ArrayList<>();
        plaintexts.add(new Plaintext(new byte[] {0}));
        plaintexts.add(new Plaintext(new byte[] {1}));
        plaintexts.add(new Plaintext(new byte[] {2}));
        plaintexts.add(new Plaintext(new byte[] {3}));
        plaintexts.add(new Plaintext(new byte[] {4}));
        plaintexts.add(new Plaintext(new byte[] {5}));
        final List<Label> labels = new ArrayList<>();
        labels.add(new Label(new byte[] {0}));
        labels.add(new Label(new byte[] {1}));
        labels.add(new Label(new byte[] {2}));
        labels.add(new Label(new byte[] {3}));
        labels.add(new Label(new byte[] {4}));
        labels.add(new Label(new byte[] {5}));
        set1.add(plaintexts.get(0));
        set1.add(plaintexts.get(1));
        set1.add(plaintexts.get(2));
        multimap.put(labels.get(0), set1);
        multimap2.put(labels.get(0), set1);
        final var set2 = new HashSet<>(plaintexts);
        multimap.put(labels.get(1), set2);
        multimap2.put(labels.get(1), set2);
        multimap.put(labels.get(2), set2);
        multimap.put(labels.get(3), set2);
        multimap.put(labels.get(4), set2);
        multimap.put(labels.get(5), set2);
    }

    @Test
    public void testCuckooHashing() throws GeneralSecurityException {
        final int alpha = 1;
        final int numberOfValues2 = VolumeHidingEMMUtils.getNumberOfValues(multimap2);
        final var table1 = new PairLabelPlaintext[(1 + alpha) * numberOfValues2];
        final var table2 = new PairLabelPlaintext[(1 + alpha) * numberOfValues2];
        final Stack<PairLabelPlaintext> stash = new Stack<>();
        VolumeHidingEMMUtils.doCuckooHashingWithStash(
                1, table1, table2, multimap2, stash, (1 + alpha) * numberOfValues2);
        assertEquals(8, Arrays.stream(table1).filter(Objects::nonNull).count());
        assertEquals(1, Arrays.stream(table2).filter(Objects::nonNull).count());
        assertEquals(0, stash.size());
    }

    @Test
    public void testCuckooHashing2() throws GeneralSecurityException {
        final int alpha = 1;
        final int numberOfValues1 = VolumeHidingEMMUtils.getNumberOfValues(multimap);
        final var table1 = new PairLabelPlaintext[(1 + alpha) * numberOfValues1];
        final var table2 = new PairLabelPlaintext[(1 + alpha) * numberOfValues1];
        final Stack<PairLabelPlaintext> stash = new Stack<>();
        VolumeHidingEMMUtils.doCuckooHashingWithStash(
                numberOfValues1 / 3,
                table1,
                table2,
                multimap,
                stash,
                (1 + alpha) * numberOfValues1);
        assertEquals(20, Arrays.stream(table1).filter(Objects::nonNull).count());
        assertEquals(2, Arrays.stream(table2).filter(Objects::nonNull).count());
        assertEquals(11, stash.size());
    }
}
