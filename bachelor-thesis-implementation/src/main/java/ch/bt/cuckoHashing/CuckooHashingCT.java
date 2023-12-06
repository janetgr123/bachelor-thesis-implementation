package ch.bt.cuckoHashing;

import ch.bt.crypto.CastingHelpers;
import ch.bt.crypto.DPRF;
import ch.bt.emm.dpVolumeHiding.DPVolumeHidingEMMUtils;
import ch.bt.model.multimap.Ciphertext;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.PairLabelNumberValues;
import ch.bt.model.multimap.Plaintext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

public class CuckooHashingCT {
    private static final Logger logger = LoggerFactory.getLogger(DPVolumeHidingEMMUtils.class);
    private static final int maxStashSize = 3;

    public static void doCuckooHashingWithStashCT(
            final int maxNumberOfEvictions,
            final PairLabelNumberValues[] table1,
            final PairLabelNumberValues[] table2,
            final Map<Label, Set<Plaintext>> multiMap,
            final Stack<Ciphertext> stash,
            final int tableSize,
            final SecretKey key)
            throws IOException {
        final var labels = multiMap.keySet();

        int evictionCounter = 0;
        for (final var label : labels) {
            final var numberOfValues = multiMap.get(label).size();
            PairLabelNumberValues toInsert = new PairLabelNumberValues(label, numberOfValues);
            boolean firstTime = true;
            while (toInsert != null && (firstTime || evictionCounter < maxNumberOfEvictions)) {
                if (firstTime) {
                    evictionCounter = 0;
                }
                logger.info("Inserting in table 1: {}", toInsert);
                toInsert = insert(table1, getHashCT(toInsert.label(), 0, tableSize, key), toInsert);
                if (toInsert != null) {
                    logger.info("COLLISION! Evict from table 1: {}", toInsert);
                    logger.info("Inserting in table 2: {}", toInsert);
                    evictionCounter++;
                    toInsert =
                            insert(
                                    table2,
                                    getHashCT(toInsert.label(), 1, tableSize, key),
                                    toInsert);
                    if (toInsert != null) {
                        logger.info("COLLISION! Evict from table 2: {}", toInsert);
                        evictionCounter++;
                        firstTime = false;
                    }
                }
            }
            if (toInsert != null) {
                logger.info("Could not insert element. Putting onto stash: {}", toInsert);
                stash.add(toInsert);
            }
        }

        if (stash.size() > maxStashSize) {
            throw new IllegalStateException("stash exceeded maximum size");
        }
    }

    public static int getHashCT(
            final Label label, final int tableNo, final int n, final SecretKey key)
            throws IOException {
        final var toHash =
                org.bouncycastle.util.Arrays.concatenate(
                        CastingHelpers.fromStringToByteArray("CT"),
                        label.label(),
                        CastingHelpers.fromIntToByteArray(tableNo));
        final var result =
                CastingHelpers.fromByteArrayToHashModN(
                        DPRF.calculateFk(
                                CastingHelpers.fromByteArrayToBitInputStream(toHash),
                                key.getEncoded()),
                        n);
        logger.info("Hashing element {}. The hash evaluates to {}.", toHash, result);
        return result;
    }

    private static PairLabelNumberValues insert(
            final PairLabelNumberValues[] table,
            final int hash,
            final PairLabelNumberValues pairLabelNumberValues) {
        PairLabelNumberValues removed = null;
        if (table[hash] != null) {
            removed = table[hash];
        }
        table[hash] = pairLabelNumberValues;
        return removed;
    }
}
