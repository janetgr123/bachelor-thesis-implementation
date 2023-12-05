package ch.bt.emm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.bt.TestConfigurations;
import ch.bt.TestConfigurationsWithDB;
import ch.bt.TestUtils;
import ch.bt.crypto.CryptoUtils;
import ch.bt.model.*;
import ch.bt.model.Label;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

@ExtendWith({TestConfigurations.class})
@ExtendWith({TestConfigurationsWithDB.class})
public class VolumeHidingEMMUtilsTest {

    private static final Map<Label, Set<Plaintext>> multimap = new HashMap<>();
    private static final Map<Label, Set<Plaintext>> multimap2 = new HashMap<>();

    private static Map<Label, Set<Plaintext>> multimapWithRealData;

    private static final double ALPHA = 0.3;

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

        multimapWithRealData = TestUtils.multimap;
    }

    @Test
    public void testCuckooHashing() throws GeneralSecurityException, IOException {
        testCuckooHashingWithMultimap(multimap);
    }

    @Test
    public void testCuckooHashing2() throws IOException, GeneralSecurityException {
        testCuckooHashingWithMultimap(multimap2);
    }

    @Test
    public void testCuckooHashingWithRealData() throws IOException, GeneralSecurityException {
        testCuckooHashingWithMultimap(multimapWithRealData);
    }

    private void testCuckooHashingWithMultimap(final Map<Label, Set<Plaintext>> multimap)
            throws GeneralSecurityException, IOException {
        final int numberOfValues = VolumeHidingEMMUtils.getNumberOfValues(multimap);
        final int size = (int) Math.round((1 + ALPHA) * numberOfValues);
        final var table1 = new PairLabelPlaintext[size];
        final var table2 = new PairLabelPlaintext[size];
        final Stack<PairLabelPlaintext> stash = new Stack<>();
        final var key = CryptoUtils.generateKeyWithHMac(256);
        VolumeHidingEMMUtils.doCuckooHashingWithStash(
                (int) Math.round(5 * Math.log(numberOfValues) / Math.log(2)),
                table1,
                table2,
                multimap,
                stash,
                size,
                key);

        // PROPERTY 1   : no elements are disappearing
        assertEquals(
                numberOfValues,
                Arrays.stream(table1).filter(Objects::nonNull).count()
                        + Arrays.stream(table2).filter(Objects::nonNull).count()
                        + stash.size());

        // PROPERTY 2:  stash size is less than numberOfValues / 10
        assertTrue(stash.size() <= numberOfValues / 10);
    }
}
