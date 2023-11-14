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
    private final SEScheme SEScheme;
    private final Hash hash;

    private final Map<PlaintextLabel, Set<PlaintextValue>> multiMap;

    private Stack<Pair> stash;

    private final int alpha;


    public VolumeHidingEMM(final SecureRandom secureRandom, final SecureRandom secureRandomSE, final int securityParameter, final int alpha, final Map<PlaintextLabel, Set<PlaintextValue>> multiMap) {
        this.secureRandom = secureRandom;
        this.secureRandomSE = secureRandomSE;
        this.alpha = alpha;
        this.multiMap = multiMap;
        final var secretKey = this.setup(securityParameter);
        this.hash = new SHA512Hash();
        this.SEScheme = new AESSEScheme(secureRandomSE, secretKey.getKey().keys().get(1));
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
        final int numberOfValues = VolumeHidingEMMUtils.getNumberOfValues(multiMap);
        final Pair[] table1 = new Pair[(alpha + 1) * numberOfValues];
        final Pair[] table2 = new Pair[(alpha + 1) * numberOfValues];
        final Stack<Pair> stash = new Stack<>();
        VolumeHidingEMMUtils.doCuckooHashingWithStash(numberOfValues, table1, table2, multiMap, stash, hash);
        VolumeHidingEMMUtils.fillEmptyValues(table1);
        VolumeHidingEMMUtils.fillEmptyValues(table2);
        this.stash = stash;

        final Pair[] encryptedTable1 = new Pair[(alpha + 1) * numberOfValues];
        final Pair[] encryptedTable2 = new Pair[(alpha + 1) * numberOfValues];
        VolumeHidingEMMUtils.encryptTables(table1, table2, encryptedTable1, encryptedTable2, SEScheme);

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
            final var token1 = VolumeHidingEMMUtils.getHash(label, i, 0, hash);
            final var token2 = VolumeHidingEMMUtils.getHash(label, i, 1, hash);
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
        final var plaintexts = values.stream().map(el -> el.decrypt(SEScheme)).filter(el -> el.getLabel().equals(label)).collect(Collectors.toSet());
        plaintexts.addAll(stash.stream().filter(el -> el.getLabel().equals(label)).collect(Collectors.toSet()));
        return plaintexts.stream().map(Pair::getValue).collect(Collectors.toSet());
    }

    public Map<PlaintextLabel, Set<PlaintextValue>> getMultiMap() {
        return multiMap;
    }


}
