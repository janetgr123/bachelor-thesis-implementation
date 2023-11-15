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

    public static final int CT = -1;

    public static int getNumberOfValues(final Map<Label, Set<Value>> multiMap) {
        int n = 0;
        final var labels = multiMap.keySet();
        for (final var label : labels) {
            n += multiMap.get(label).size();
        }
        return n;
    }

    public static void doCuckooHashingWithStash(
            final int maxStashSize,
            final PairLabelValue[] table1,
            final PairLabelValue[] table2,
            final Map<Label, Set<Value>> multiMap,
            final Stack<PairLabelValue> stash,
            final Hash hash,
            final int tableSize) {
        final var labels = multiMap.keySet();

        final Map<Label, List<Value>> indices = new HashMap<>();
        for (final var label : labels) {
            final var values = multiMap.get(label).stream().toList();
            indices.put(label, values);
        }

        int evictionCounter = 0;
        for (final var label : labels) {
            final var values = indices.get(label);
            for (final var value : values) {
                PairLabelValue toInsert = new PairLabelValue(label, value);
                while (evictionCounter < Math.log(tableSize) && toInsert != null) {
                    logger.debug("Inserting in table 1: {}", toInsert);
                    toInsert =
                            insert(
                                    table1,
                                    getHash(
                                            toInsert.label(),
                                            values.indexOf(toInsert.value()),
                                            0,
                                            hash,
                                            tableSize),
                                    toInsert);
                    if (toInsert != null) {
                        logger.debug("COLLISION! Evict from table 1: {}", toInsert);
                        logger.debug("Inserting in table 2: {}", toInsert);
                        evictionCounter++;
                        toInsert =
                                insert(
                                        table2,
                                        getHash(
                                                toInsert.label(),
                                                values.indexOf(toInsert.value()),
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

    public static void doCuckooHashingWithStashCT(
            final int maxStashSize,
            final PairLabelNumberValues[] table1,
            final PairLabelNumberValues[] table2,
            final Map<Label, Set<Value>> multiMap,
            final Stack<PairLabelNumberValues> stash,
            final Hash hash,
            final int tableSize) {
        final var labels = multiMap.keySet();

        int evictionCounter = 0;
        for (final var label : labels) {
            final var numberOfValues = multiMap.get(label).size();
            PairLabelNumberValues toInsert = new PairLabelNumberValues(label, numberOfValues);
            while (evictionCounter < Math.log(tableSize) && toInsert != null) {
                logger.debug("Inserting in table 1: {}", toInsert);
                toInsert =
                        insert(table1, getHashCT(toInsert.label(), 0, hash, tableSize), toInsert);
                if (toInsert != null) {
                    logger.debug("COLLISION! Evict from table 1: {}", toInsert);
                    logger.debug("Inserting in table 2: {}", toInsert);
                    evictionCounter++;
                    toInsert =
                            insert(
                                    table2,
                                    getHashCT(toInsert.label(), 1, hash, tableSize),
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

        if (stash.size() > maxStashSize) {
            throw new IllegalStateException("stash exceeded maximum size");
        }
    }

    public static int getHash(
            final Label label, final int i, final int tableNo, final Hash hash, final int n) {
        final var toHash =
                org.bouncycastle.util.Arrays.concatenate(
                        label.label(),
                        BigInteger.valueOf(i).toByteArray(),
                        BigInteger.valueOf(tableNo).toByteArray());
        logger.debug(
                "Hashing element {}. The hash evaluates to {}.",
                toHash,
                Math.floorMod(Arrays.hashCode(hash.hash(toHash)), n));
        return Math.floorMod(Arrays.hashCode(hash.hash(toHash)), n);
    }

    public static int getHashCT(
            final Label label, final int tableNo, final Hash hash, final int n) {
        final var toHash =
                org.bouncycastle.util.Arrays.concatenate(
                        BigInteger.valueOf(CT).toByteArray(),
                        label.label(),
                        BigInteger.valueOf(tableNo).toByteArray());
        logger.debug(
                "Hashing element {}. The hash evaluates to {}.",
                toHash,
                Math.floorMod(Arrays.hashCode(hash.hash(toHash)), n));
        return Math.floorMod(Arrays.hashCode(hash.hash(toHash)), n);
    }

    private static PairLabelValue insert(
            final PairLabelValue[] table, final int hash, final PairLabelValue pairLabelValue) {
        PairLabelValue removed = null;
        if (table[hash] != null) {
            removed = table[hash];
        }
        table[hash] = pairLabelValue;
        return removed;
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

    public static void encryptTables(
            final PairLabelValue[] table1,
            final PairLabelValue[] table2,
            final PairLabelValue[] encryptedTable1,
            final PairLabelValue[] encryptedTable2,
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

    public static void encryptCounterTables(
            final PairLabelNumberValues[] table1,
            final PairLabelNumberValues[] table2,
            final PairLabelNumberValues[] encryptedTable1,
            final PairLabelNumberValues[] encryptedTable2,
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

    public static void fillEmptyValues(final PairLabelValue[] table) {
        int i = 0;
        for (final var pair : table) {
            if (pair == null) {
                table[i] = new PairLabelValue(new Label(new byte[0]), new Value(new byte[0]));
            }
            i++;
        }
    }

    public static void fillEmptyValues(final PairLabelNumberValues[] table) {
        int i = 0;
        for (final var pair : table) {
            if (pair == null) {
                table[i] = new PairLabelNumberValues(new Label(new byte[0]), 0);
            }
            i++;
        }
    }

    public static List<Label> getDecryptedLabels(
            final VolumeHidingEMM volumeHidingEMM,
            final PairLabelValue[] table1,
            final PairLabelValue[] table2) {
        final var labelsTable1 = Arrays.stream(table1).map(PairLabelValue::label).toList();
        final var labelsTable2 = Arrays.stream(table2).map(PairLabelValue::label).toList();
        final var labelsTables = new ArrayList<>(labelsTable1);
        labelsTables.addAll(labelsTable2);
        return labelsTables.stream()
                .map(el -> volumeHidingEMM.getSeScheme().decrypt(el.label()))
                .map(Label::new)
                .distinct()
                .sorted()
                .toList();
    }

    public static List<Value> getDecryptedValues(
            final VolumeHidingEMM volumeHidingEMM,
            final PairLabelValue[] table1,
            final PairLabelValue[] table2) {
        final var valuesTable1 = Arrays.stream(table1).map(PairLabelValue::value).toList();
        final var valuesTable2 = Arrays.stream(table2).map(PairLabelValue::value).toList();
        final var valuesTables = new ArrayList<>(valuesTable1);
        valuesTables.addAll(valuesTable2);
        return valuesTables.stream()
                .map(el -> volumeHidingEMM.getSeScheme().decrypt(el.value()))
                .map(Value::new)
                .distinct()
                .sorted()
                .toList();
    }
}
