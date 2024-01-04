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

/**
 * This class is a collection of static helper methods for {@link ch.bt.emm.dpVolumeHiding}
 *
 * @author Janet Greutmann
 */
public class DPVolumeHidingEMMUtils {
    /** Dummy entry */
    public static final byte[] DUMMY = new byte[0];

    /**
     * @param tableSize the size of the tables
     * @param numberOfValues the number of values stored in the multimap
     * @param multiMap the multimap containing the plaintext data
     * @param prfKey the secret key used for the PRF
     * @param seScheme the symmetric encryption scheme
     * @return the encrypted index of the counter tables calculated with Cuckoo Hashing, the tables
     *     are encrypted, the stash is not.
     * @throws IOException
     */
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

    /**
     * @param entry the (label, |multimap[label]|) pair that should be encrypted
     * @param seScheme the symmetric encryption scheme
     * @return the encrypted (label, |multimap[label]|) pair
     * @throws GeneralSecurityException
     */
    private static PairLabelCiphertext encryptEntry(
            final PairLabelNumberValues entry, final SEScheme seScheme)
            throws GeneralSecurityException {
        return new PairLabelCiphertext(
                seScheme.encryptLabel(entry.label()),
                seScheme.encrypt(
                        new Plaintext(CastingHelpers.fromIntToByteArray(entry.numberOfValues()))));
    }

    /**
     * Encrypts the Cuckoo Hashing counter tables
     *
     * @param table1 the first counter table of the Cuckoo Hashing
     * @param table2 the second counter table of the Cuckoo Hashing
     * @param encryptedTable1 the reference to the resulting encrypted table 1
     * @param encryptedTable2 the reference to the resulting encrypted table 2
     * @param seScheme the symmetric encryption scheme
     */
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

    /**
     * Fills empty entries of the counter table with dummy values
     *
     * @param table one of the two counter tables used for Cuckoo Hashing
     * @return the number of dummy entries in the counter table
     */
    public static int fillEmptyValues(final PairLabelNumberValues[] table) {
        int numberOfDummyCT = 0;
        int i = 0;
        for (final var pair : table) {
            if (pair == null) {
                table[i] = new PairLabelNumberValues(new Label(DUMMY), 0);
                numberOfDummyCT++;
            }
            i++;
        }
        return numberOfDummyCT;
    }

    /**
     * @param volumeHidingEMM the differentially private volume hiding emm
     * @param table1 the first encrypted table of the Cuckoo Hashing
     * @param table2 the second encrypted table of the Cuckoo Hashing
     * @return a list of all decrypted labels that are contained in the two tables
     */
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

    /**
     * @param volumeHidingEMM the differentially private volume hiding emm
     * @param table1 the first encrypted table of the Cuckoo Hashing
     * @param table2 the second encrypted table of the Cuckoo Hashing
     * @return a list of all decrypted values that are contained in the two tables
     */
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
