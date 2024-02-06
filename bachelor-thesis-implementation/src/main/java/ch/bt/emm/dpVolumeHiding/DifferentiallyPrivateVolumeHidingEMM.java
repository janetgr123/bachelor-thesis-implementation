package ch.bt.emm.dpVolumeHiding;

import ch.bt.crypto.*;
import ch.bt.emm.TwoRoundEMM;
import ch.bt.emm.volumeHiding.VolumeHidingEMMUtils;
import ch.bt.model.encryptedindex.DifferentiallyPrivateEncryptedIndexTables;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexTables;
import ch.bt.model.multimap.*;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.searchtoken.SearchTokenBytes;
import ch.bt.model.searchtoken.SearchTokenIntBytes;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

import javax.crypto.SecretKey;

/**
 * This class implements the Differentially Private Volume Hiding SSE scheme from <a
 * href="https://doi.org/10.1145/3319535.3354213">Patel et al.</a>
 *
 * @author Janet Greutmann
 */
public class DifferentiallyPrivateVolumeHidingEMM implements TwoRoundEMM {
    /** correction factor for the laplace distribution sampling */
    private static final int correctionFactor = 160; // t = 16

    /** the privacy budget for differential privacy */
    private final double epsilon;

    /** Factor to calculate table size for Cuckoo Hashing */
    private final double alpha;

    /** the stash for the Cuckoo Hashing of the counter table */
    private Stack<Ciphertext> counterStash;

    /** the stash for the Cuckoo Hashing */
    private Stack<Ciphertext> stash;

    /** Symmetric encryption scheme */
    private final SEScheme seScheme;

    /** The secret key for the PRF */
    private final SecretKey prfKey;

    /** the size of the tables used for the Cuckoo Hashing */
    private int tableSize;

    /** the maximum number of values per label (used for padding) */
    private int maxNumberOfValuesPerLabel = 0;

    /** the number of dummy entries in the encrypted tables */
    private int numberOfDummyValues;

    /** the number of dummy entries in the encrypted counter tables */
    private int numberOfDummyCT;

    /** the key dependent laplacian distribution */
    private final KeyDependentLaplaceDistribution laplaceDistribution;

    public DifferentiallyPrivateVolumeHidingEMM(
            final int securityParameter, final double epsilon, final double alpha)
            throws GeneralSecurityException {
        final var keys = this.setup(securityParameter);
        this.prfKey = keys.get(0);
        this.seScheme = new AESSEScheme(keys.get(1));
        this.alpha = alpha;
        this.epsilon = epsilon;
        this.laplaceDistribution = new KeyDependentLaplaceDistribution(0, 2 / epsilon);
    }

    /**
     * Determines and sets the size of the padding
     *
     * @param multiMap the multimap containing the plaintext data
     */
    private void setMaxNumberOfValuesPerLabel(final Map<Label, Set<Plaintext>> multiMap) {
        final var keys = multiMap.keySet();
        for (final var key : keys) {
            final var num = multiMap.get(key).size();
            if (num > maxNumberOfValuesPerLabel) {
                maxNumberOfValuesPerLabel = num;
            }
        }
    }

    /**
     * @param securityParameter the length of the keys in bits
     * @return two secret keys, one for the PRF and one for the symmetric encryption scheme
     * @throws GeneralSecurityException
     */
    @Override
    public List<SecretKey> setup(int securityParameter) throws GeneralSecurityException {
        final var key1 = CryptoUtils.generateKeyWithHMac(securityParameter);
        final var key2 = CryptoUtils.generateKeyForAES(securityParameter);
        return List.of(key1, key2);
    }

    /**
     * @param multiMap the plaintext data stored in a multimap
     * @return the encrypted index of the multimap according to the scheme specified in the
     *     mentioned paper.
     * @throws GeneralSecurityException
     */
    @Override
    public EncryptedIndex buildIndex(final Map<Label, Set<Plaintext>> multiMap)
            throws GeneralSecurityException, IOException {
        final int numberOfValues = VolumeHidingEMMUtils.getNumberOfValues(multiMap);
        this.tableSize = (int) Math.round((1 + alpha) * numberOfValues);

        // determine padding
        setMaxNumberOfValuesPerLabel(multiMap);

        /*
         * Cuckoo Hashing
         */
        final var encryptedIndexWithStash =
                VolumeHidingEMMUtils.calculateEncryptedIndexAndStash(
                        tableSize, numberOfValues, multiMap, prfKey, seScheme);

        final var encryptedIndex = encryptedIndexWithStash.encryptedIndex();
        this.stash = encryptedIndexWithStash.stash();
        this.numberOfDummyValues = encryptedIndexWithStash.numberOfDummyValues();

        /*
         * Cuckoo Hashing for counter tables
         */
        final var encryptedCTIndexWithStash =
                DPVolumeHidingEMMUtils.calculateEncryptedCTIndex(
                        tableSize, numberOfValues, multiMap, prfKey, seScheme);
        final var encryptedCTIndex = encryptedCTIndexWithStash.encryptedIndex();
        this.counterStash = encryptedCTIndexWithStash.stash();
        this.numberOfDummyCT = encryptedCTIndexWithStash.numberOfDummyValues();

        return new DifferentiallyPrivateEncryptedIndexTables(encryptedIndex, encryptedCTIndex);
    }

    /**
     * @param searchLabel the search label in plaintext
     * @return a search token that enables access to the entries in the encrypted index counter
     *     tables that correspond to the search label.
     * @throws GeneralSecurityException
     */
    @Override
    public SearchToken trapdoor(final Label searchLabel)
            throws GeneralSecurityException, IOException {
        return new SearchTokenBytes(
                DPRF.generateToken(
                        prfKey,
                        new Label(
                                org.bouncycastle.util.Arrays.concatenate(
                                        CastingHelpers.fromStringToByteArray("CT"),
                                        searchLabel.label()))));
    }

    /**
     * @param label the search label in plaintext
     * @param ciphertexts the ciphertexts of the counter table returned by search
     * @return a search token that enables access to the entry in the encrypted index that
     *     corresponds to the search label.
     * @throws GeneralSecurityException
     */
    @Override
    public SearchToken trapdoor(final Label label, final Set<Ciphertext> ciphertexts)
            throws GeneralSecurityException, IOException {
        final var encryptedLabel = seScheme.encryptLabel(label);
        final var matchingEntries =
                ciphertexts.stream()
                        .map(PairLabelCiphertext.class::cast)
                        .filter(el -> el.label().equals(encryptedLabel))
                        .count();
        final var matchingEntriesInStash =
                counterStash.stream()
                        .map(PairLabelPlaintext.class::cast)
                        .filter(el -> el.label().equals(label))
                        .count();
        final var noise = laplaceDistribution.sample(label.label());
        var numberOfValuesWithNoise =
                (int) (matchingEntries + matchingEntriesInStash + correctionFactor + noise);
        final var token = DPRF.generateToken(prfKey, label);
        return new SearchTokenIntBytes(numberOfValuesWithNoise, token);
    }

    /**
     * @param searchToken the search token that has been generated with trapdoor
     * @param encryptedIndex the encrypted index of the counter tables
     * @return the set of ciphertexts in the counter tables that correspond to the label encrypted
     *     in the token
     */
    @Override
    public Set<Ciphertext> search(
            final SearchToken searchToken, final EncryptedIndex encryptedIndex) throws IOException {
        if (!(encryptedIndex instanceof DifferentiallyPrivateEncryptedIndexTables)
                || !(searchToken instanceof SearchTokenBytes)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        Set<Ciphertext> ciphertexts = new HashSet<>();
        final var encryptedCouterIndex =
                (EncryptedIndexTables)
                        ((DifferentiallyPrivateEncryptedIndexTables) encryptedIndex)
                                .encryptedIndexCT();
        final var encryptedCounterTable = encryptedCouterIndex.getTable(0);
        final var encryptedCounterTable2 = encryptedCouterIndex.getTable(1);
        final var token = ((SearchTokenBytes) searchToken).token();
        final var expand1 =
                CastingHelpers.fromByteArrayToHashModN(DPRF.evaluateDPRF(token, 0), tableSize);
        final var expand2 =
                CastingHelpers.fromByteArrayToHashModN(DPRF.evaluateDPRF(token, 1), tableSize);
        final var ciphertext1 = encryptedCounterTable[expand1];
        final var ciphertext2 = encryptedCounterTable2[expand2];
        ciphertexts.add(ciphertext1);
        ciphertexts.add(ciphertext2);
        return ciphertexts;
    }

    /**
     * @param searchToken the search token that has been generated with trapdoor(label, ciphertexts)
     * @param encryptedIndex the encrypted index of the value tables
     * @return the set of ciphertexts that correspond to the label encrypted in the token
     */
    @Override
    public Set<Ciphertext> search2(
            final SearchToken searchToken, final EncryptedIndex encryptedIndex) throws IOException {
        if (!(encryptedIndex instanceof DifferentiallyPrivateEncryptedIndexTables)
                || !(searchToken instanceof SearchTokenIntBytes token)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        Set<Ciphertext> ciphertexts = new HashSet<>();
        final var encryptedIndexTables =
                (EncryptedIndexTables)
                        ((DifferentiallyPrivateEncryptedIndexTables) encryptedIndex)
                                .encryptedIndex();
        final var encryptedIndexTable1 = encryptedIndexTables.getTable(0);
        final var encryptedIndexTable2 = encryptedIndexTables.getTable(1);
        final var numberOfValues = token.token();
        int i = 0;
        while (i < numberOfValues) {
            final var expand1 =
                    CastingHelpers.fromByteArrayToHashModN(
                            DPRF.evaluateDPRF(token.token2(), i, 0), tableSize);
            final var expand2 =
                    CastingHelpers.fromByteArrayToHashModN(
                            DPRF.evaluateDPRF(token.token2(), i, 1), tableSize);
            final var ciphertext1 = encryptedIndexTable1[expand1];
            final var ciphertext2 = encryptedIndexTable2[expand2];
            ciphertexts.add(ciphertext1);
            ciphertexts.add(ciphertext2);
            i++;
        }
        return ciphertexts;
    }

    /**
     * @param ciphertexts the set of ciphertexts that search2 found for a given token
     * @param searchLabel the search label in plaintext
     * @return the set of plaintexts that have been encrypted to those ciphertexts using the given
     *     ivs and the schemeKey
     */
    @Override
    public Set<Plaintext> result(Set<Ciphertext> ciphertexts, Label searchLabel)
            throws GeneralSecurityException {
        return VolumeHidingEMMUtils.getPlaintexts(ciphertexts, seScheme, searchLabel, stash);
    }

    /**
     * Getter for the encryption scheme
     *
     * @return the encryption scheme instance
     */
    @Override
    public SEScheme getSeScheme() {
        return seScheme;
    }

    /**
     * Getter for the number of dummy entries in the encrypted index
     *
     * @return the number of dummy values in the value tables
     */
    @Override
    public int getNumberOfDummyValues() {
        return numberOfDummyValues;
    }

    /**
     * Getter for the number of dummy entries in the encrypted index
     *
     * @return the number of dummy values in the counter tables
     */
    @Override
    public int getNumberOfDummyCT() {
        return numberOfDummyCT;
    }
}
