package ch.bt.emm.volumeHiding;

import ch.bt.crypto.SEScheme;
import ch.bt.cuckoHashing.CuckooHashing;
import ch.bt.model.EncryptedIndexWithStash;
import ch.bt.model.encryptedindex.EncryptedIndexTables;
import ch.bt.model.multimap.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

public class VolumeHidingEMMUtils {

    public static int getNumberOfValues(final Map<Label, Set<Plaintext>> multiMap) {
        int n = 0;
        final var labels = multiMap.keySet();
        for (final var label : labels) {
            n += multiMap.get(label).size();
        }
        return n;
    }

    public static EncryptedIndexWithStash calculateEncryptedIndexAndStash(
            final int tableSize,
            final int numberOfValues,
            final Map<Label, Set<Plaintext>> multiMap,
            final SecretKey prfKey,
            final SEScheme seScheme)
            throws IOException {
        int maxNumberOfEvictions = (int) Math.round(5 * Math.log(numberOfValues) / Math.log(2));

        final PairLabelPlaintext[] table1 = new PairLabelPlaintext[tableSize];
        final PairLabelPlaintext[] table2 = new PairLabelPlaintext[tableSize];
        final Stack<Ciphertext> stash = new Stack<>();
        CuckooHashing.doCuckooHashingWithStash(
                maxNumberOfEvictions, table1, table2, multiMap, stash, tableSize, prfKey);
        VolumeHidingEMMUtils.fillEmptyValues(table1);
        VolumeHidingEMMUtils.fillEmptyValues(table2);

        final PairLabelCiphertext[] encryptedTable1 = new PairLabelCiphertext[tableSize];
        final PairLabelCiphertext[] encryptedTable2 = new PairLabelCiphertext[tableSize];
        VolumeHidingEMMUtils.encryptTables(
                table1, table2, encryptedTable1, encryptedTable2, seScheme);

        return new EncryptedIndexWithStash(
                new EncryptedIndexTables(encryptedTable1, encryptedTable2), stash);
    }

    public static Set<Plaintext> getPlaintexts(
            final Set<Ciphertext> ciphertexts,
            final SEScheme seScheme,
            final Label searchLabel,
            final Stack<Ciphertext> stash) {
        final var plaintexts =
                ciphertexts.stream()
                        .map(PairLabelCiphertext.class::cast)
                        .map(
                                el -> {
                                    try {
                                        return new PairLabelPlaintext(
                                                seScheme.decryptLabel(el.label()),
                                                seScheme.decrypt(el.value()));
                                    } catch (GeneralSecurityException e) {
                                        throw new RuntimeException(e);
                                    }
                                })
                        .map(PairLabelPlaintext.class::cast)
                        .filter(el -> !Arrays.equals(el.label().label(), new byte[0]))
                        .filter(el -> searchLabel.equals(el.label()))
                        .map(PairLabelPlaintext::value)
                        .collect(Collectors.toSet());
        plaintexts.addAll(
                stash.stream()
                        .map(PairLabelPlaintext.class::cast)
                        .filter(el -> searchLabel.equals(el.label()))
                        .map(PairLabelPlaintext::value)
                        .collect(Collectors.toSet()));
        return plaintexts;
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
