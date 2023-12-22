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

/** SSE scheme from Patel et al. (2019) */
public class VolumeHidingEMM implements EMM {
    private final SEScheme seScheme;
    private int tableSize;

    private Stack<Ciphertext> stash;
    private final double alpha;

    private final SecretKey prfKey;
    private final SecretKey aesKey;

    private int maxNumberOfValuesPerLabel = 0;

    private int numberOfDummyValues;

    public VolumeHidingEMM(final int securityParameter, final double alpha)
            throws GeneralSecurityException {
        final var keys = this.setup(securityParameter);
        this.prfKey = keys.get(0);
        this.aesKey = keys.get(1);
        this.seScheme = new AESSEScheme(aesKey);
        this.alpha = alpha;
    }

    // for benchmarking only
    public VolumeHidingEMM(
            final double alpha,
            final int maxNumberOfValuesPerLabel,
            final int tableSize,
            final SecretKey prfKey,
            final SecretKey seSchemeKey) {
        this.prfKey = prfKey;
        this.aesKey = seSchemeKey;
        this.seScheme = new AESSEScheme(seSchemeKey);
        this.alpha = alpha;
        this.maxNumberOfValuesPerLabel = maxNumberOfValuesPerLabel;
        this.tableSize = tableSize;
    }

    private void setMaxNumberOfValuesPerLabel(final Map<Label, Set<Plaintext>> multiMap) {
        final var keys = multiMap.keySet();
        for (final var key : keys) {
            final var num = multiMap.get(key).size();
            if (num > maxNumberOfValuesPerLabel) {
                maxNumberOfValuesPerLabel = num;
            }
        }
    }

    @Override
    public List<SecretKey> setup(final int securityParameter) throws GeneralSecurityException {
        final var key1 = CryptoUtils.generateKeyWithHMac(securityParameter);
        final var key2 = CryptoUtils.generateKeyForAES(securityParameter);
        return List.of(key1, key2);
    }

    @Override
    public EncryptedIndex buildIndex(final Map<Label, Set<Plaintext>> multiMap)
            throws GeneralSecurityException, IOException {
        setMaxNumberOfValuesPerLabel(multiMap);
        final int numberOfValues = VolumeHidingEMMUtils.getNumberOfValues(multiMap);
        this.tableSize = (int) Math.round((1 + alpha) * numberOfValues);
        final var encryptedIndexWithStash =
                VolumeHidingEMMUtils.calculateEncryptedIndexAndStash(
                        tableSize, numberOfValues, multiMap, prfKey, seScheme);
        this.stash = encryptedIndexWithStash.stash();
        this.numberOfDummyValues = encryptedIndexWithStash.numberOfDummyValues();
        return encryptedIndexWithStash.encryptedIndex();
    }

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

    @Override
    public Set<Plaintext> result(final Set<Ciphertext> ciphertexts, final Label searchLabel)
            throws GeneralSecurityException {
        return VolumeHidingEMMUtils.getPlaintexts(ciphertexts, seScheme, searchLabel, stash);
    }

    public SEScheme getSeScheme() {
        return seScheme;
    }

    public int getTableSize() {
        return tableSize;
    }

    public SecretKey getPrfKey() {
        return prfKey;
    }

    @Override
    public SecretKey getAesKey() {
        return aesKey;
    }

    public int getMaxNumberOfValuesPerLabel() {
        return maxNumberOfValuesPerLabel;
    }

    public int getNumberOfDummyValues() {
        return numberOfDummyValues;
    }
}
