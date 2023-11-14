package ch.bt.emm;

import ch.bt.crypto.Hash;
import ch.bt.crypto.SEScheme;
import ch.bt.model.*;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

public class VolumeHidingEMMUtils {

    public static int getNumberOfValues(final Map<PlaintextLabel, Set<PlaintextValue>> multiMap) {
        int n = 0;
        final var labels = multiMap.keySet();
        for (final var label : labels) {
            n += multiMap.get(label).size();
        }
        return n;
    }

    public static void doCuckooHashingWithStash(final int numberOfValues, final Pair[] table1, final Pair[] table2, final Map<PlaintextLabel, Set<PlaintextValue>> multiMap, final Stack<Pair> stash, final Hash hash, final int n) {
        final var labels = multiMap.keySet();
        int evictionCounter = 0;
        for (final var label : labels) {
            int valueCounter = 0;
            final var values = multiMap.get(label);
            for (final var value : values) {
                Pair toInsert = new Pair(label, value);
                while (evictionCounter < Math.log(numberOfValues) && toInsert != null) {
                    toInsert = insert(table1, getHash(toInsert.getLabel(), valueCounter, 0, hash, n), toInsert);
                    if (toInsert != null) {
                        evictionCounter++;
                        toInsert = insert(table2, getHash(toInsert.getLabel(), valueCounter, 1, hash, n), toInsert);
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
    }

    public static int getHash(final Label label, final int i, final int tableNo, final Hash hash, final int n) {
        final var toHash = org.bouncycastle.util.Arrays.concatenate(label.getLabel(), BigInteger.valueOf(i).toByteArray(), BigInteger.valueOf(tableNo).toByteArray());
        return Math.floorMod(Arrays.hashCode(hash.hash(toHash)), n);
    }

    private static Pair insert(final Pair[] table, final int hash, final Pair pair) {
        Pair removed = null;
        if (table[hash] != null) {
            removed = table[hash];
        }
        table[hash] = pair;
        return removed;
    }

    public static void encryptTables(final Pair[] table1, final Pair[] table2, final Pair[] encryptedTable1, final Pair[] encryptedTable2, final SEScheme SEScheme) {
        if (table1.length != table2.length) {
            throw new IllegalArgumentException("table sizes must match");
        }
        final var pairsTable1 = Arrays.stream(table1).map(entry -> SEScheme.encrypt(entry)).toList();
        final var pairsTable2 = Arrays.stream(table2).map(entry -> SEScheme.encrypt(entry)).toList();
        int i = 0;
        while (i < pairsTable1.size()) {
            encryptedTable1[i] = pairsTable1.get(i);
            encryptedTable2[i] = pairsTable2.get(i);
            i++;
        }
    }

    public static void fillEmptyValues(final Pair[] table) {
        int i = 0;
        for (final var pair : table) {
            if (pair == null) {
                table[i] = new Pair(new PlaintextLabel(new byte[0]), new PlaintextValue(new byte[0]));
            }
            i++;
        }
    }
}
