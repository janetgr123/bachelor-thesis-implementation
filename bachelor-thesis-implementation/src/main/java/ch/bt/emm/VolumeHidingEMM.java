package ch.bt.emm;

import ch.bt.crypto.*;
import ch.bt.model.*;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

/**
 * SSE scheme from Patel et al. (2019)
 */

public class VolumeHidingEMM implements EMM {
    private final SecureRandom secureRandom;
    private final SecureRandom secureRandomSE;

    private final SecretKey secretKey;

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
        secretKey = this.setup(securityParameter);
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
        final int numberOfValues = getNumberOfValues();
        final Pair[] table1 = new Pair[(alpha + 1) * numberOfValues];
        final Pair[] table2 = new Pair[(alpha + 1) * numberOfValues];
        doCuckooHashingWithStash(numberOfValues, table1, table2);

        final Pair[] encryptedTable1 = new Pair[(alpha + 1) * numberOfValues];
        final Pair[] encryptedTable2 = new Pair[(alpha + 1) * numberOfValues];
        encryptTables(table1, table2, encryptedTable1, encryptedTable2);

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
            final var token1 = getHash(label, i, 0);
            final var token2 = getHash(label, i, 1);
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

    private int getHash(final Label label, final int i, final int tableNo) {
        final var toHash = org.bouncycastle.util.Arrays.concatenate(label.getLabel(), BigInteger.valueOf(i).toByteArray(), BigInteger.valueOf(tableNo).toByteArray());
        return hash.hash(toHash).hashCode();
    }

    private Pair insert(final Pair[] table, final int hash, final Pair pair) {
        Pair removed = null;
        if (table[hash] != null) {
            removed = table[hash];
        }
        table[hash] = pair;
        return removed;
    }

    public Map<PlaintextLabel, Set<PlaintextValue>> getMultiMap() {
        return multiMap;
    }

    private int getNumberOfValues() {
        int n = 0;
        final var labels = multiMap.keySet();
        for (final var label : labels) {
            n += multiMap.get(label).size();
        }
        return n;
    }

    private void doCuckooHashingWithStash(final int numberOfValues, final Pair[] table1, final Pair[] table2) {
        final Stack<Pair> stash = new Stack<>();
        final var labels = multiMap.keySet();
        int evictionCounter = 0;
        for (final var label : labels) {
            int valueCounter = 0;
            final var values = multiMap.get(label);
            for (final var value : values) {
                Pair toInsert = new Pair(label, value);
                while (evictionCounter < Math.log(numberOfValues) && toInsert != null) {
                    toInsert = insert(table1, getHash(toInsert.getLabel(), valueCounter, 0), toInsert);
                    if (toInsert != null) {
                        evictionCounter++;
                        toInsert = insert(table2, getHash(toInsert.getLabel(), valueCounter, 1), toInsert);
                        if (toInsert != null) {
                            evictionCounter++;
                        }
                    }
                }
                if (toInsert != null) {
                    stash.add(toInsert);
                }
                valueCounter++;
            }
        }

        if (stash.size() > numberOfValues) {
            throw new IllegalStateException("stash exceeded maximum size");
        }

        this.stash = stash;
    }

    private void encryptTables(final Pair[] table1, final Pair[] table2, final Pair[] encryptedTable1, final Pair[] encryptedTable2) {
        if (table1.length != table2.length) {
            throw new IllegalArgumentException("table sizes must match");
        }
        final var pairsTable1 = Arrays.stream(table1).map(entry -> entry.encrypt(SEScheme)).toList();
        final var pairsTable2 = Arrays.stream(table2).map(entry -> entry.encrypt(SEScheme)).toList();
        int i = 0;
        while (i < pairsTable1.size()) {
            encryptedTable1[i] = pairsTable1.get(i);
            encryptedTable2[i] = pairsTable2.get(i);
            i++;
        }
    }
}
