package ch.bt.emm;

import ch.bt.crypto.*;
import ch.bt.model.*;
import ch.bt.model.Label;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexTables;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.searchtoken.SearchTokenInts;
import ch.bt.model.searchtoken.SearchTokenListInts;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

/** SSE scheme from Patel et al. (2019) */
public class VolumeHidingEMM implements EMM {
    private final SEScheme seScheme;
    private int maxStashSize;
    private int tableSize;

    private int maxNumberOfEvictions;
    private Stack<PairLabelPlaintext> stash;
    private final double alpha;

    private final SecretKey prfKey;

    private int maxNumberOfValuesPerLabel = 0;

    public VolumeHidingEMM(final int securityParameter, final double alpha)
            throws GeneralSecurityException {
        final var keys = this.setup(securityParameter);
        this.prfKey = keys.get(0);
        this.seScheme = new AESSEScheme(keys.get(1));
        this.alpha = alpha;
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
        this.maxNumberOfEvictions = (int) Math.round(5 * Math.log(numberOfValues) / Math.log(2));
        this.maxStashSize = numberOfValues;

        final PairLabelPlaintext[] table1 = new PairLabelPlaintext[tableSize];
        final PairLabelPlaintext[] table2 = new PairLabelPlaintext[tableSize];
        final Stack<PairLabelPlaintext> stash = new Stack<>();
        VolumeHidingEMMUtils.doCuckooHashingWithStash(
                maxNumberOfEvictions, table1, table2, multiMap, stash, tableSize, prfKey);
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
    public SearchToken trapdoor(final Label searchLabel)
            throws GeneralSecurityException, IOException {
        final var token = new ArrayList<SearchTokenInts>();
        int i = 0;
        while (i < maxNumberOfValuesPerLabel) {
            final var token1 = VolumeHidingEMMUtils.getHash(searchLabel, i, 0, tableSize, prfKey);
            final var token2 = VolumeHidingEMMUtils.getHash(searchLabel, i, 1, tableSize, prfKey);
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
        token.forEach(
                t -> {
                    ciphertexts.add(encryptedIndexTable1[t.getToken(1)]);
                    ciphertexts.add(encryptedIndexTable2[t.getToken(2)]);
                });
        return ciphertexts;
    }

    @Override
    public Set<Plaintext> result(final Set<Ciphertext> ciphertexts, final Label searchLabel)
            throws GeneralSecurityException {
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
                        .filter(el -> searchLabel.equals(el.label()))
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

    public int getMaxNumberOfEvictions() {
        return maxNumberOfEvictions;
    }

    public SecretKey getPrfKey() {
        return prfKey;
    }

    public int getMaxNumberOfValuesPerLabel() {
        return maxNumberOfValuesPerLabel;
    }
}
