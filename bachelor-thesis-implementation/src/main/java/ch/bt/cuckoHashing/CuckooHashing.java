package ch.bt.cuckoHashing;

import ch.bt.crypto.CastingHelpers;
import ch.bt.crypto.DPRF;
import ch.bt.emm.dpVolumeHiding.DPVolumeHidingEMMUtils;
import ch.bt.model.multimap.Ciphertext;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.PairLabelPlaintext;
import ch.bt.model.multimap.Plaintext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

import javax.crypto.SecretKey;

public class CuckooHashing {
    private static final Logger logger = LoggerFactory.getLogger(DPVolumeHidingEMMUtils.class);
    private static final int maxStashSize = 3;

    public static void doCuckooHashingWithStash(
            final int maxNumberOfEvictions,
            final PairLabelPlaintext[] table1,
            final PairLabelPlaintext[] table2,
            final Map<Label, Set<Plaintext>> multiMap,
            final Stack<Ciphertext> stash,
            final int tableSize,
            final SecretKey key)
            throws IOException {
        final var labels = multiMap.keySet();

        final Map<PairLabelPlaintext, Integer> indices = new HashMap<>();
        for (final var label : labels) {
            final var values = multiMap.get(label).stream().toList();
            int i = 0;
            for (final var value : values) {
                PairLabelPlaintext pair = new PairLabelPlaintext(label, value);
                indices.put(pair, i);
                i++;
            }
        }

        int evictionCounter = 0;
        for (final var label : labels) {
            final var values = multiMap.get(label);
            for (final var value : values) {
                PairLabelPlaintext toInsert = new PairLabelPlaintext(label, value);
                boolean firstTime = true;
                while (toInsert != null && (firstTime || evictionCounter < maxNumberOfEvictions)) {
                    if (firstTime) {
                        evictionCounter = 0;
                    }
                    logger.info("Inserting in table 1: {}", toInsert);
                    toInsert =
                            insert(
                                    table1,
                                    getHash(
                                            toInsert.label(),
                                            indices.get(toInsert),
                                            0,
                                            tableSize,
                                            key),
                                    toInsert);
                    if (toInsert != null) {
                        logger.info("COLLISION! Evict from table 1: {}", toInsert);
                        logger.info("Inserting in table 2: {}", toInsert);
                        evictionCounter++;
                        toInsert =
                                insert(
                                        table2,
                                        getHash(
                                                toInsert.label(),
                                                indices.get(toInsert),
                                                1,
                                                tableSize,
                                                key),
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
        }

        if (stash.size() > maxStashSize) {
            throw new IllegalStateException("stash exceeded maximum size");
        }
    }

    public static int getHash(
            final Label label, final int i, final int tableNo, final int n, final SecretKey key)
            throws IOException {
        final var toHash =
                org.bouncycastle.util.Arrays.concatenate(
                        label.label(),
                        CastingHelpers.fromIntToByteArray(i),
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

    private static PairLabelPlaintext insert(
            final PairLabelPlaintext[] table,
            final int hash,
            final PairLabelPlaintext pairLabelPlaintext) {
        PairLabelPlaintext removed = null;
        if (table[hash] != null) {
            removed = table[hash];
        }
        table[hash] = pairLabelPlaintext;
        return removed;
    }
}
