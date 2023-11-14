package ch.bt.emm;

import ch.bt.crypto.*;
import ch.bt.model.*;

import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

/**
 * SSE scheme from Patel et al. (2019)
 */

public class VolumeHidingEMM implements EMM {
    private final SecureRandom secureRandom;
    private final SecureRandom secureRandomSE;
    private final SEScheme seScheme;
    private final Hash hash;

    private final Map<PlaintextLabel, Set<PlaintextValue>> multiMap;
    private final int maxStashSize;
    private final int tableSize;
    private Stack<Pair> stash;


    public VolumeHidingEMM(final SecureRandom secureRandom, final SecureRandom secureRandomSE, final int securityParameter, final int alpha, final Map<PlaintextLabel, Set<PlaintextValue>> multiMap) {
        this.secureRandom = secureRandom;
        this.secureRandomSE = secureRandomSE;
        this.multiMap = multiMap;
        final var secretKey = this.setup(securityParameter);
        this.hash = new SHA512Hash();
        this.seScheme = new AESSEScheme(secureRandomSE, secretKey.getKey().keys().get(1));
        final int numberOfValues = VolumeHidingEMMUtils.getNumberOfValues(multiMap);
        this.tableSize = (1 + alpha) * numberOfValues;
        this.maxStashSize = numberOfValues;
    }

    /**
     * @param securityParameter
     * @return
     */
    @Override
    public SecretKey setup(final int securityParameter) {
        final var key1 = new KeyGenerator(secureRandom, securityParameter).generateKey();
        final var key2 = new KeyGenerator(secureRandomSE, securityParameter).generateKey();
        return new SecretKeyPair(key1, key2);
    }

    @Override
    public EncryptedIndex buildIndex() {
        final Pair[] table1 = new Pair[tableSize];
        final Pair[] table2 = new Pair[tableSize];
        final Stack<Pair> stash = new Stack<>();
        VolumeHidingEMMUtils.doCuckooHashingWithStash(maxStashSize, table1, table2, multiMap, stash, hash, tableSize);
        VolumeHidingEMMUtils.fillEmptyValues(table1);
        VolumeHidingEMMUtils.fillEmptyValues(table2);
        this.stash = stash;

        final Pair[] encryptedTable1 = new Pair[tableSize];
        final Pair[] encryptedTable2 = new Pair[tableSize];
        VolumeHidingEMMUtils.encryptTables(table1, table2, encryptedTable1, encryptedTable2, seScheme);

        return new EncryptedIndexTables(encryptedTable1, encryptedTable2);
    }

    /**
     * @param label
     * @return
     */
    @Override
    public SearchToken trapdoor(final Label label) {
        final var valueSetSize = multiMap.get(label).size();
        final var token = new ArrayList<SearchTokenInts>();
        int i = 0;
        while (i < valueSetSize) {
            final var token1 = VolumeHidingEMMUtils.getHash(label, i, 0, hash, tableSize);
            final var token2 = VolumeHidingEMMUtils.getHash(label, i, 1, hash, tableSize);
            token.add(new SearchTokenInts(token1, token2));
            i++;
        }
        return new SearchTokenListInts(token);
    }

    /**
     * @param searchToken
     * @param encryptedIndex
     * @return
     */
    @Override
    public Set<Pair> search(final SearchToken searchToken, final EncryptedIndex encryptedIndex) {
        if (!(encryptedIndex instanceof EncryptedIndexTables) || !(searchToken instanceof SearchTokenListInts)) {
            throw new IllegalArgumentException("types of encrypted index or search token are not matching");
        }
        Set<Pair> ciphertexts = new HashSet<>();
        final var encryptedIndexTable1 = ((EncryptedIndexTables) encryptedIndex).getTable(0);
        final var encryptedIndexTable2 = ((EncryptedIndexTables) encryptedIndex).getTable(1);
        final var token = ((SearchTokenListInts) searchToken).getSearchTokenList();
        token.forEach(t -> {
            ciphertexts.add(encryptedIndexTable1[t.getToken(1)]);
            ciphertexts.add(encryptedIndexTable2[t.getToken(2)]);
        });
        return ciphertexts;
    }

    /**
     * @param values
     * @param label
     * @return
     */
    @Override
    public Set<Value> result(final Set<Pair> values, final Label label) {
        final var plaintexts = values.stream().map(el -> seScheme.decrypt(el)).filter(el -> el.getLabel().equals(label)).collect(Collectors.toSet());
        plaintexts.addAll(stash.stream().filter(el -> el.getLabel().equals(label)).collect(Collectors.toSet()));
        return plaintexts.stream().map(Pair::getValue).collect(Collectors.toSet());
    }

    public Map<PlaintextLabel, Set<PlaintextValue>> getMultiMap() {
        return multiMap;
    }


}
