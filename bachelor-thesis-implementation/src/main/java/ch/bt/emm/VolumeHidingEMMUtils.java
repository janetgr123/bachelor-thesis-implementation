package ch.bt.emm;

import ch.bt.crypto.Hash;
import ch.bt.crypto.SEScheme;
import ch.bt.model.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.*;

public class VolumeHidingEMMUtils {

    private static final Logger logger = LoggerFactory.getLogger(VolumeHidingEMMUtils.class);

    public static int getNumberOfValues(final Map<PlaintextLabel, Set<PlaintextValue>> multiMap) {
        int n = 0;
        final var labels = multiMap.keySet();
        for (final var label : labels) {
            n += multiMap.get(label).size();
        }
        return n;
    }

    public static void doCuckooHashingWithStash(
            final int maxStashSize,
            final Pair[] table1,
            final Pair[] table2,
            final Map<PlaintextLabel, Set<PlaintextValue>> multiMap,
            final Stack<Pair> stash,
            final Hash hash,
            final int tableSize) {
        final var labels = multiMap.keySet();

        final Map<Label, List<PlaintextValue>> indices = new HashMap<>();
        for(final var label : labels){
            final var values = multiMap.get(label).stream().toList();
            indices.put(label, values);
        }

        int evictionCounter = 0;
        for (final var label : labels) {
            final var values = indices.get(label);
            for (final var value : values) {
                Pair toInsert = new Pair(label, value);
                while (evictionCounter < Math.log(tableSize) && toInsert != null) {
                    logger.debug("Inserting in table 1: {}", toInsert);
                    toInsert =
                            insert(
                                    table1,
                                    getHash(toInsert.getLabel(), values.indexOf(toInsert.getValue()), 0, hash, tableSize),
                                    toInsert);
                    if (toInsert != null) {
                        logger.debug("COLLISION! Evict from table 1: {}", toInsert);
                        logger.debug("Inserting in table 2: {}", toInsert);
                        evictionCounter++;
                        toInsert =
                                insert(
                                        table2,
                                        getHash(
                                                toInsert.getLabel(),
                                                values.indexOf(toInsert.getValue()),
                                                1,
                                                hash,
                                                tableSize),
                                        toInsert);
                        if (toInsert != null) {
                            logger.debug("COLLISION! Evict from table 2: {}", toInsert);
                            evictionCounter++;
                        }
                    }
                }
                if (toInsert != null) {
                    logger.debug("Could not insert element. Putting onto stash: {}", toInsert);
                    stash.add(toInsert);
                }
            }
        }

        if (stash.size() > maxStashSize) {
            throw new IllegalStateException("stash exceeded maximum size");
        }
    }

    public static int getHash(
            final Label label, final int i, final int tableNo, final Hash hash, final int n) {
        final var toHash =
                org.bouncycastle.util.Arrays.concatenate(
                        label.getLabel(),
                        BigInteger.valueOf(i).toByteArray(),
                        BigInteger.valueOf(tableNo).toByteArray());
        logger.debug(
                "Hashing element {}. The hash evaluates to {}.",
                toHash,
                Math.floorMod(Arrays.hashCode(hash.hash(toHash)), n));
        return Math.floorMod(Arrays.hashCode(hash.hash(toHash)), n);
    }

    private static Pair insert(final Pair[] table, final int hash, final Pair pair) {
        Pair removed = null;
        if (table[hash] != null) {
            removed = table[hash];
        }
        table[hash] = pair;
        return removed;
    }

    public static void encryptTables(
            final Pair[] table1,
            final Pair[] table2,
            final Pair[] encryptedTable1,
            final Pair[] encryptedTable2,
            final SEScheme SEScheme) {
        if (table1.length != table2.length) {
            throw new IllegalArgumentException("table sizes must match");
        }
        final var pairsTable1 = Arrays.stream(table1).map(SEScheme::encrypt).toList();
        final var pairsTable2 = Arrays.stream(table2).map(SEScheme::encrypt).toList();
        int i = 0;
        while (i < pairsTable1.size()) {
            encryptedTable1[i] = pairsTable1.get(i);
            encryptedTable2[i] = pairsTable2.get(i);
            i++;
        }
    }

    public static void fillEmptyValues(final Pair[] table) {
        int i = 0;
        for (final var pair : table) {
            if (pair == null) {
                table[i] =
                        new Pair(new PlaintextLabel(new byte[0]), new PlaintextValue(new byte[0]));
            }
            i++;
        }
    }
}
