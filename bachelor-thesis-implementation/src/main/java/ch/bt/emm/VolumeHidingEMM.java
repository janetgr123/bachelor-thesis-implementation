package ch.bt.emm;

import ch.bt.crypto.*;
import ch.bt.model.*;
import ch.bt.model.Label;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexTables;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.searchtoken.SearchTokenInts;
import ch.bt.model.searchtoken.SearchTokenListInts;

import java.security.GeneralSecurityException;
import java.util.*;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

/** SSE scheme from Patel et al. (2019) */
public class VolumeHidingEMM implements EMM {
    private final SEScheme seScheme;
    private int maxStashSize;
    private int tableSize;
    private Stack<PairLabelPlaintext> stash;
    private final int alpha;
    private Map<Label, Set<Plaintext>> multiMap;

    private Label searchLabel;

    public VolumeHidingEMM(final int securityParameter, final int alpha)
            throws GeneralSecurityException {
        final var secretKeys = this.setup(securityParameter);
        this.seScheme = new AESSEScheme(secretKeys.get(1));
        this.alpha = alpha;
    }

    @Override
    public List<SecretKey> setup(final int securityParameter) throws GeneralSecurityException {
        final var key1 = CryptoUtils.generateKeyWithHMac(securityParameter);
        final var key2 = CryptoUtils.generateKeyForAES(securityParameter);
        return List.of(key1, key2);
    }

    @Override
    public EncryptedIndex buildIndex(final Map<Label, Set<Plaintext>> multiMap)
            throws GeneralSecurityException {
        this.multiMap = multiMap;
        final int numberOfValues = VolumeHidingEMMUtils.getNumberOfValues(multiMap);
        this.tableSize = (1 + alpha) * numberOfValues;
        this.maxStashSize = numberOfValues;

        final PairLabelPlaintext[] table1 = new PairLabelPlaintext[tableSize];
        final PairLabelPlaintext[] table2 = new PairLabelPlaintext[tableSize];
        final Stack<PairLabelPlaintext> stash = new Stack<>();
        VolumeHidingEMMUtils.doCuckooHashingWithStash(
                maxStashSize, table1, table2, multiMap, stash, tableSize);
        VolumeHidingEMMUtils.fillEmptyValues(table1);
        VolumeHidingEMMUtils.fillEmptyValues(table2);
        this.stash = stash;

        final PairLabelCiphertext[] encryptedTable1 = new PairLabelCiphertext[tableSize];
        final PairLabelCiphertext[] encryptedTable2 = new PairLabelCiphertext[tableSize];
        VolumeHidingEMMUtils.encryptTables(
                table1, table2, encryptedTable1, encryptedTable2, seScheme);

        return new EncryptedIndexTables(encryptedTable1, encryptedTable2);
    }

    @Override
    public SearchToken trapdoor(final Label searchLabel) throws GeneralSecurityException {
        this.searchLabel = searchLabel;
        final var valueSet = multiMap.get(searchLabel);
        int valueSetSize = 0;
        if (valueSet != null) {
            valueSetSize = valueSet.size();
        }
        final var token = new ArrayList<SearchTokenInts>();
        int i = 0;
        while (i < valueSetSize) {
            final var token1 = VolumeHidingEMMUtils.getHash(searchLabel, i, 0, tableSize);
            final var token2 = VolumeHidingEMMUtils.getHash(searchLabel, i, 1, tableSize);
            token.add(new SearchTokenInts(token1, token2));
            i++;
        }
        return new SearchTokenListInts(token);
    }

    @Override
    public Set<Ciphertext> search(
            final SearchToken searchToken, final EncryptedIndex encryptedIndex) {
        if (!(encryptedIndex instanceof EncryptedIndexTables)
                || !(searchToken instanceof SearchTokenListInts)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        Set<Ciphertext> ciphertexts = new HashSet<>();
        final var encryptedIndexTable1 = ((EncryptedIndexTables) encryptedIndex).getTable(0);
        final var encryptedIndexTable2 = ((EncryptedIndexTables) encryptedIndex).getTable(1);
        final var token = ((SearchTokenListInts) searchToken).getSearchTokenList();
        token.forEach(
                t -> {
                    ciphertexts.add(encryptedIndexTable1[t.getToken(1)]);
                    ciphertexts.add(encryptedIndexTable2[t.getToken(2)]);
                });
        return ciphertexts;
    }

    @Override
    public Set<Plaintext> result(final Set<Ciphertext> ciphertexts)
            throws GeneralSecurityException {
        final var encryptedSearchLabel = seScheme.encryptLabel(searchLabel);
        final var plaintexts =
                ciphertexts.stream()
                        .map(PairLabelCiphertext.class::cast)
                        .filter(el -> el.label().equals(encryptedSearchLabel))
                        .map(PairLabelCiphertext::value)
                        .map(
                                ciphertextWithIV -> {
                                    try {
                                        return seScheme.decrypt(ciphertextWithIV);
                                    } catch (GeneralSecurityException e) {
                                        throw new RuntimeException(e);
                                    }
                                })
                        .collect(Collectors.toSet());
        plaintexts.addAll(
                stash.stream()
                        .filter(el -> el.label().equals(searchLabel))
                        .map(PairLabelPlaintext::value)
                        .collect(Collectors.toSet()));
        return plaintexts;
    }

    public SEScheme getSeScheme() {
        return seScheme;
    }

    public int getTableSize() {
        return tableSize;
    }

    public int getMaxStashSize() {
        return maxStashSize;
    }

    public void setSearchLabel(final Label label) {
        this.searchLabel = label;
    }
}
