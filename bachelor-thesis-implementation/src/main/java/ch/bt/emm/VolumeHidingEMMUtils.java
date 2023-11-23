package ch.bt.emm;

import ch.bt.crypto.CastingHelpers;
import ch.bt.crypto.DPRF;
import ch.bt.crypto.SEScheme;
import ch.bt.model.*;
import ch.bt.model.Label;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

import javax.crypto.SecretKey;

public class VolumeHidingEMMUtils {

    private static final Logger logger = LoggerFactory.getLogger(VolumeHidingEMMUtils.class);

    public static int getNumberOfValues(final Map<Label, Set<Plaintext>> multiMap) {
        int n = 0;
        final var labels = multiMap.keySet();
        for (final var label : labels) {
            n += multiMap.get(label).size();
        }
        return n;
    }

    public static void doCuckooHashingWithStash(
            final int maxNumberOfEvictions,
            final int maxStashSize,
            final PairLabelPlaintext[] table1,
            final PairLabelPlaintext[] table2,
            final Map<Label, Set<Plaintext>> multiMap,
            final Stack<PairLabelPlaintext> stash,
            final int tableSize, final SecretKey key) throws IOException {
        final var labels = multiMap.keySet();

        final Map<Label, List<Plaintext>> indices = new HashMap<>();
        for (final var label : labels) {
            final var values = multiMap.get(label).stream().toList();
            indices.put(label, values);
        }

        int evictionCounter = 0;
        for (final var label : labels) {
            final var values = indices.get(label);
            for (final var value : values) {
                PairLabelPlaintext toInsert = new PairLabelPlaintext(label, value);
                while (evictionCounter < maxNumberOfEvictions && toInsert != null) {
                    logger.debug("Inserting in table 1: {}", toInsert);
                    toInsert =
                            insert(
                                    table1,
                                    getHash(
                                            toInsert.label(),
                                            values.indexOf(toInsert.value()),
                                            0,
                                            tableSize, key),
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
                                                tableSize, key),
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
            final int maxNumberOfEvictions,
            final int maxStashSize,
            final PairLabelNumberValues[] table1,
            final PairLabelNumberValues[] table2,
            final Map<Label, Set<Plaintext>> multiMap,
            final Stack<PairLabelNumberValues> stash,
            final int tableSize, final SecretKey key) throws IOException {
        final var labels = multiMap.keySet();

        int evictionCounter = 0;
        for (final var label : labels) {
            final var numberOfValues = multiMap.get(label).size();
            PairLabelNumberValues toInsert = new PairLabelNumberValues(label, numberOfValues);
            while (evictionCounter < maxNumberOfEvictions && toInsert != null) {
                logger.debug("Inserting in table 1: {}", toInsert);
                toInsert = insert(table1, getHashCT(toInsert.label(), 0, tableSize, key), toInsert);
                if (toInsert != null) {
                    logger.debug("COLLISION! Evict from table 1: {}", toInsert);
                    logger.debug("Inserting in table 2: {}", toInsert);
                    evictionCounter++;
                    toInsert = insert(table2, getHashCT(toInsert.label(), 1, tableSize, key), toInsert);
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
        logger.debug("Hashing element {}. The hash evaluates to {}.", toHash, result);
        return result;
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
        logger.debug("Hashing element {}. The hash evaluates to {}.", toHash, result);
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
            final PairLabelPlaintext[] table1,
            final PairLabelPlaintext[] table2,
            final PairLabelCiphertext[] encryptedTable1,
            final PairLabelCiphertext[] encryptedTable2,
            final SEScheme seScheme) {
        if (table1.length != table2.length) {
            throw new IllegalArgumentException("table sizes must match");
        }
        final var pairsTable1 =
                Arrays.stream(table1)
                        .map(
                                el -> {
                                    try {
                                        return encryptEntry(el, seScheme);
                                    } catch (GeneralSecurityException e) {
                                        throw new RuntimeException(e);
                                    }
                                })
                        .toList();
        final var pairsTable2 =
                Arrays.stream(table2)
                        .map(
                                el -> {
                                    try {
                                        return encryptEntry(el, seScheme);
                                    } catch (GeneralSecurityException e) {
                                        throw new RuntimeException(e);
                                    }
                                })
                        .toList();
        int i = 0;
        while (i < pairsTable1.size()) {
            encryptedTable1[i] = pairsTable1.get(i);
            encryptedTable2[i] = pairsTable2.get(i);
            i++;
        }
    }

    private static PairLabelCiphertext encryptEntry(
            final PairLabelPlaintext entry, final SEScheme seScheme)
            throws GeneralSecurityException {
        return new PairLabelCiphertext(
                seScheme.encryptLabel(entry.label()), seScheme.encrypt(entry.value()));
    }

    private static PairLabelCiphertext encryptEntry(
            final PairLabelNumberValues entry, final SEScheme seScheme)
            throws GeneralSecurityException {
        return new PairLabelCiphertext(
                seScheme.encryptLabel(entry.label()),
                seScheme.encrypt(
                        new Plaintext(CastingHelpers.fromIntToByteArray(entry.numberOfValues()))));
    }

    public static void encryptCounterTables(
            final PairLabelNumberValues[] table1,
            final PairLabelNumberValues[] table2,
            final PairLabelCiphertext[] encryptedTable1,
            final PairLabelCiphertext[] encryptedTable2,
            final SEScheme seScheme) {
        if (table1.length != table2.length) {
            throw new IllegalArgumentException("table sizes must match");
        }
        final var pairsTable1 =
                Arrays.stream(table1)
                        .map(
                                el -> {
                                    try {
                                        return encryptEntry(el, seScheme);
                                    } catch (GeneralSecurityException e) {
                                        throw new RuntimeException(e);
                                    }
                                })
                        .toList();
        final var pairsTable2 =
                Arrays.stream(table2)
                        .map(
                                el -> {
                                    try {
                                        return encryptEntry(el, seScheme);
                                    } catch (GeneralSecurityException e) {
                                        throw new RuntimeException(e);
                                    }
                                })
                        .toList();
        int i = 0;
        while (i < pairsTable1.size()) {
            encryptedTable1[i] = pairsTable1.get(i);
            encryptedTable2[i] = pairsTable2.get(i);
            i++;
        }
    }

    public static void fillEmptyValues(final PairLabelPlaintext[] table) {
        int i = 0;
        for (final var pair : table) {
            if (pair == null) {
                table[i] =
                        new PairLabelPlaintext(new Label(new byte[0]), new Plaintext(new byte[0]));
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
            final PairLabelCiphertext[] table1,
            final PairLabelCiphertext[] table2) {
        final var labelsTable1 = Arrays.stream(table1).map(PairLabelCiphertext::label).toList();
        final var labelsTable2 = Arrays.stream(table2).map(PairLabelCiphertext::label).toList();
        final var labelsTables = new ArrayList<>(labelsTable1);
        labelsTables.addAll(labelsTable2);
        return labelsTables.stream()
                .map(
                        el -> {
                            try {
                                return volumeHidingEMM.getSeScheme().decryptLabel(el);
                            } catch (GeneralSecurityException e) {
                                throw new RuntimeException(e);
                            }
                        })
                .distinct()
                .sorted()
                .toList();
    }

    public static List<Plaintext> getDecryptedValues(
            final VolumeHidingEMM volumeHidingEMM,
            final PairLabelCiphertext[] table1,
            final PairLabelCiphertext[] table2) {
        final var valuesTable1 = Arrays.stream(table1).map(PairLabelCiphertext::value).toList();
        final var valuesTable2 = Arrays.stream(table2).map(PairLabelCiphertext::value).toList();
        final var valuesTables = new ArrayList<>(valuesTable1);
        valuesTables.addAll(valuesTable2);
        return valuesTables.stream()
                .map(
                        el -> {
                            try {
                                return volumeHidingEMM.getSeScheme().decrypt(el);
                            } catch (GeneralSecurityException e) {
                                throw new RuntimeException(e);
                            }
                        })
                .distinct()
                .sorted()
                .toList();
    }
}
