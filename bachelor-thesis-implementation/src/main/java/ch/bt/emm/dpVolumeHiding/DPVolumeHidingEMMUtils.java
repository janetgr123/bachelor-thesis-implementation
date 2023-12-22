package ch.bt.emm.dpVolumeHiding;

import ch.bt.crypto.CastingHelpers;
import ch.bt.crypto.SEScheme;
import ch.bt.cuckoHashing.CuckooHashingCT;
import ch.bt.model.EncryptedIndexWithStash;
import ch.bt.model.encryptedindex.EncryptedIndexTables;
import ch.bt.model.multimap.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

import javax.crypto.SecretKey;

public class DPVolumeHidingEMMUtils {

    public static EncryptedIndexWithStash calculateEncryptedCTIndex(
            final int tableSize,
            final int numberOfValues,
            final Map<Label, Set<Plaintext>> multiMap,
            final SecretKey prfKey,
            final SEScheme seScheme)
            throws IOException {
        int maxNumberOfEvictions = (int) Math.round(5 * Math.log(numberOfValues) / Math.log(2));
        final PairLabelNumberValues[] counterTable1 = new PairLabelNumberValues[tableSize];
        final PairLabelNumberValues[] counterTable2 = new PairLabelNumberValues[tableSize];
        final Stack<Ciphertext> counterStash = new Stack<>();
        CuckooHashingCT.doCuckooHashingWithStashCT(
                maxNumberOfEvictions,
                counterTable1,
                counterTable2,
                multiMap,
                counterStash,
                tableSize,
                prfKey);
        int numberOfDummyCT = DPVolumeHidingEMMUtils.fillEmptyValues(counterTable1);
        numberOfDummyCT += DPVolumeHidingEMMUtils.fillEmptyValues(counterTable2);

        final PairLabelCiphertext[] encryptedCounterTable1 = new PairLabelCiphertext[tableSize];
        final PairLabelCiphertext[] encryptedCounterTable2 = new PairLabelCiphertext[tableSize];
        DPVolumeHidingEMMUtils.encryptCounterTables(
                counterTable1,
                counterTable2,
                encryptedCounterTable1,
                encryptedCounterTable2,
                seScheme);
        return new EncryptedIndexWithStash(
                new EncryptedIndexTables(encryptedCounterTable1, encryptedCounterTable2),
                counterStash,
                numberOfDummyCT);
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

    public static int fillEmptyValues(final PairLabelNumberValues[] table) {
        int numberOfDummyCT = 0;
        int i = 0;
        for (final var pair : table) {
            if (pair == null) {
                table[i] = new PairLabelNumberValues(new Label(new byte[0]), 0);
                numberOfDummyCT++;
            }
            i++;
        }
        return numberOfDummyCT;
    }

    public static List<Label> getDecryptedLabels(
            final DifferentiallyPrivateVolumeHidingEMM volumeHidingEMM,
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
            final DifferentiallyPrivateVolumeHidingEMM volumeHidingEMM,
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
