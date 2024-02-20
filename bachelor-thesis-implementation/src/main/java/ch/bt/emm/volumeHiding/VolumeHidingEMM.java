package ch.bt.emm.volumeHiding;

import ch.bt.crypto.*;
import ch.bt.cuckoHashing.CuckooHashing;
import ch.bt.emm.EMM;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexTables;
import ch.bt.model.multimap.*;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.searchtoken.SearchTokenInts;
import ch.bt.model.searchtoken.SearchTokenListInts;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

import javax.crypto.SecretKey;

/**
 * This class implements the Volume Hiding SSE scheme from <a
 * href="https://doi.org/10.1145/3319535.3354213">Patel et al.</a>
 *
 * @author Janet Greutmann
 */
public class VolumeHidingEMM implements EMM {
    /** Symmetric encryption scheme */
    private final SEScheme seScheme;

    /** the size of the tables used for the Cuckoo Hashing */
    private int tableSize;

    /** the stash for the Cuckoo Hashing */
    private Stack<Ciphertext> stash;

    /** Factor to calculate table size for Cuckoo Hashing */
    private final double alpha;

    /** The secret key for the PRF */
    private final SecretKey prfKey;

    /** the maximum number of values per label (used for padding) */
    private int maxNumberOfValuesPerLabel = 0;

    /** the size of dummy entries in bytes in the encrypted tables */
    private int numberOfDummyValues;

    public VolumeHidingEMM(final int securityParameter, final double alpha)
            throws GeneralSecurityException {
        final var keys = this.setup(securityParameter);
        this.prfKey = keys.get(0);
        final var aesKey = keys.get(1);
        this.seScheme = new AESSEScheme(aesKey);
        this.alpha = alpha;
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
    public List<SecretKey> setup(final int securityParameter) throws GeneralSecurityException {
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
        setMaxNumberOfValuesPerLabel(multiMap);
        final int numberOfValues = VolumeHidingEMMUtils.getNumberOfValues(multiMap);
        this.tableSize = (int) Math.round((1 + alpha) * numberOfValues);

        /*
         * Cuckoo Hashing
         */
        final var encryptedIndexWithStash =
                VolumeHidingEMMUtils.calculateEncryptedIndexAndStash(
                        tableSize, numberOfValues, multiMap, prfKey, seScheme);

        this.stash = encryptedIndexWithStash.stash();
        this.numberOfDummyValues = encryptedIndexWithStash.numberOfDummyValues() * 32 * 2;
        return encryptedIndexWithStash.encryptedIndex();
    }

    /**
     * @param searchLabel the search label in plaintext
     * @return a search token that enables access to the entries in the encrypted index that
     *     correspond to the search label.
     * @throws GeneralSecurityException
     */
    @Override
    public SearchToken trapdoor(final Label searchLabel)
            throws GeneralSecurityException, IOException {
        final var token = new ArrayList<SearchTokenInts>();
        int i = 0;
        while (i < maxNumberOfValuesPerLabel) {
            final var token1 = CuckooHashing.getHash(searchLabel, i, 0, tableSize, prfKey);
            final var token2 = CuckooHashing.getHash(searchLabel, i, 1, tableSize, prfKey);
            token.add(new SearchTokenInts(token1, token2));
            i++;
        }
        return new SearchTokenListInts(token);
    }

    /**
     * @param searchToken the search token that has been generated with trapdoor
     * @param encryptedIndex the encrypted index
     * @return the set of ciphertexts that correspond to the label encrypted in the token
     * @throws GeneralSecurityException
     */
    @Override
    public Set<Ciphertext> search(
            final SearchToken searchToken, final EncryptedIndex encryptedIndex)
            throws GeneralSecurityException, IOException {
        if (!(encryptedIndex instanceof EncryptedIndexTables)
                || !(searchToken instanceof SearchTokenListInts)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        Set<Ciphertext> ciphertexts = new HashSet<>();
        final var encryptedIndexTable1 = ((EncryptedIndexTables) encryptedIndex).getTable(0);
        final var encryptedIndexTable2 = ((EncryptedIndexTables) encryptedIndex).getTable(1);
        final var token = ((SearchTokenListInts) searchToken).getSearchTokenList();
        for (final var t : token) {
            final var ciphertext1 = encryptedIndexTable1[t.getToken(1)];
            final var ciphertext2 = encryptedIndexTable2[t.getToken(2)];
            ciphertexts.add(ciphertext1);
            ciphertexts.add(ciphertext2);
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
    public Set<Plaintext> result(final Set<Ciphertext> ciphertexts, final Label searchLabel)
            throws GeneralSecurityException {
        return VolumeHidingEMMUtils.getPlaintexts(ciphertexts, seScheme, searchLabel, stash);
    }

    /**
     * Getter for the encryption scheme
     *
     * @return the encryption scheme instance
     */
    public SEScheme getSeScheme() {
        return seScheme;
    }

    /**
     * Getter for the table size (because of inheritence)
     *
     * @return the size of the Cuckoo Hashing tables
     */
    public int getTableSize() {
        return tableSize;
    }

    /**
     * Getter for the PRF key (because of inheritence)
     *
     * @return the PRF key
     */
    @Override
    public SecretKey getPrfKey() {
        return prfKey;
    }

    /**
     * Getter for the padding (because of inheritence)
     *
     * @return the maximum number of values per label
     */
    public int getMaxNumberOfValuesPerLabel() {
        return maxNumberOfValuesPerLabel;
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
}
