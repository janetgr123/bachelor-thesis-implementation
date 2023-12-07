package ch.bt.emm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.bt.TestConfigurations;
import ch.bt.TestConfigurationsWithDB;
import ch.bt.TestUtils;
import ch.bt.crypto.CryptoUtils;
import ch.bt.cuckoHashing.CuckooHashing;
import ch.bt.cuckoHashing.CuckooHashingCT;
import ch.bt.emm.volumeHiding.VolumeHidingEMMUtils;
import ch.bt.model.multimap.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

@ExtendWith({TestConfigurations.class})
@ExtendWith({TestConfigurationsWithDB.class})
public class VolumeHidingEMMUtilsTest {

    private static Map<Label, Set<Plaintext>> multimap = new HashMap<>();
    private static Map<Label, Set<Plaintext>> multimap2 = new HashMap<>();

    private static Map<Label, Set<Plaintext>> multimapWithRealData;

    private static final double ALPHA = 0.3;

    @BeforeAll
    public static void init() {
        multimap = TestUtils.multimapSmall;
        multimap2 = TestUtils.multimapSmall2;
        multimapWithRealData = TestUtils.multimap;
    }

    @Test
    public void testCuckooHashingWithSmallMap() throws GeneralSecurityException, IOException {
        testCuckooHashingWithMultimap(multimap);
        testCuckooHashingCTWithMultimap(multimap);
    }

    @Test
    public void testCuckooHashingWithSmallMap2() throws IOException, GeneralSecurityException {
        testCuckooHashingWithMultimap(multimap2);
        testCuckooHashingCTWithMultimap(multimap2);
    }

    @Test
    public void testCuckooHashingWithRealData() throws IOException, GeneralSecurityException {
        testCuckooHashingWithMultimap(multimapWithRealData);
        testCuckooHashingCTWithMultimap(multimapWithRealData);
    }

    private void testCuckooHashingWithMultimap(final Map<Label, Set<Plaintext>> multimap)
            throws GeneralSecurityException, IOException {
        final int numberOfValues = VolumeHidingEMMUtils.getNumberOfValues(multimap);
        final int size = (int) Math.round((1 + ALPHA) * numberOfValues);
        final var table1 = new PairLabelPlaintext[size];
        final var table2 = new PairLabelPlaintext[size];
        final Stack<Ciphertext> stash = new Stack<>();
        final var key = CryptoUtils.generateKeyWithHMac(256);
        CuckooHashing.doCuckooHashingWithStash(
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

    private void testCuckooHashingCTWithMultimap(final Map<Label, Set<Plaintext>> multimap)
            throws GeneralSecurityException, IOException {
        final int numberOfValues = VolumeHidingEMMUtils.getNumberOfValues(multimap);
        final int size = (int) Math.round((1 + ALPHA) * numberOfValues);
        final var table1 = new PairLabelNumberValues[size];
        final var table2 = new PairLabelNumberValues[size];
        final Stack<Ciphertext> stash = new Stack<>();
        final var key = CryptoUtils.generateKeyWithHMac(256);
        CuckooHashingCT.doCuckooHashingWithStashCT(
                (int) Math.round(5 * Math.log(numberOfValues) / Math.log(2)),
                table1,
                table2,
                multimap,
                stash,
                size,
                key);

        // PROPERTY 1   : no elements are disappearing
        assertEquals(
                multimap.size(),
                Arrays.stream(table1).filter(Objects::nonNull).count()
                        + Arrays.stream(table2).filter(Objects::nonNull).count()
                        + stash.size());

        // PROPERTY 2:  stash size is less than numberOfValues / 10
        assertTrue(stash.size() <= numberOfValues / 10);
    }
}
