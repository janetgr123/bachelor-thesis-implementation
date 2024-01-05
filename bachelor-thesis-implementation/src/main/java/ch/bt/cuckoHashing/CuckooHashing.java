package ch.bt.cuckoHashing;

import ch.bt.crypto.CastingHelpers;
import ch.bt.crypto.DPRF;
import ch.bt.model.multimap.Ciphertext;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.PairLabelPlaintext;
import ch.bt.model.multimap.Plaintext;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

import javax.crypto.SecretKey;

/**
 * This class implements the Cuckoo Hashing with Stash from <a
 * href="https://doi.org/10.1145/2508859.2516668">Kirsch et al.</a>.
 *
 * @author Janet Greutmann
 */
public class CuckooHashing {

    /** The maximum stash size should be of asymptotically constant size. */
    private static final int maxStashSize = 3;

    /**
     * @param maxNumberOfEvictions the maximum number of evictions which should be of order 5 *
     *     log2(number of values in the multimap)
     * @param table1 the first table of the cuckoo hashing with plaintext values
     * @param table2 the second table of the cuckoo hashing with plaintext values
     * @param multiMap the multimap containing the plaintext data
     * @param stash the stash that is used for cuckoo hashing
     * @param tableSize the size of the tables which is (1 + alpha) * number of values in the
     *     multimap
     * @param key the symmetric key used for the DPRF hashing
     * @throws IOException
     */
    public static void doCuckooHashingWithStash(
            final int maxNumberOfEvictions,
            final PairLabelPlaintext[] table1,
            final PairLabelPlaintext[] table2,
            final Map<Label, Set<Plaintext>> multiMap,
            final Stack<Ciphertext> stash,
            final int tableSize,
            final SecretKey key)
            throws IOException {
        /*
         * Initialisation process: create a lookup table for the value indices
         */
        final var labels = multiMap.keySet();

        final Map<PairLabelPlaintext, Integer> indices = new HashMap<>();
        for (final var label : labels) {
            final var values = multiMap.get(label).stream().toList();
            int i = 0;
            for (final var value : values) {
                PairLabelPlaintext pair = new PairLabelPlaintext(label, value);
                indices.put(pair, i);
                i++;
            }
        }

        /*
         * Cuckoo Hashing process
         */
        int evictionCounter = 0;
        for (final var label : labels) {
            final var values = multiMap.get(label);
            for (final var value : values) {
                PairLabelPlaintext toInsert = new PairLabelPlaintext(label, value);
                boolean firstTime = true;
                /*
                 * if an element is evicted, it needs to be inserted in the other table
                 * or - if the number of evictions is reached - put onto the stash
                 */
                while (toInsert != null && (firstTime || evictionCounter < maxNumberOfEvictions)) {
                    /*
                     * reset eviction counter after successful insertion process
                     */
                    if (firstTime) {
                        evictionCounter = 0;
                    }

                    /*
                     * try table 1
                     */
                    toInsert =
                            insert(
                                    table1,
                                    getHash(
                                            toInsert.label(),
                                            indices.get(toInsert),
                                            0,
                                            tableSize,
                                            key),
                                    toInsert);

                    /*
                     * if an element is evicted, try table 2
                     */
                    if (toInsert != null) {
                        evictionCounter++;
                        toInsert =
                                insert(
                                        table2,
                                        getHash(
                                                toInsert.label(),
                                                indices.get(toInsert),
                                                1,
                                                tableSize,
                                                key),
                                        toInsert);

                        /*
                         * if an element is evicted, try table 1 again in the next loop round
                         */
                        if (toInsert != null) {
                            evictionCounter++;
                            firstTime = false;
                        }
                    }
                }

                /*
                 * number of evictions is reached, the evicted element is put onto the stash
                 */
                if (toInsert != null) {
                    stash.add(toInsert);
                }
            }
        }

        if (stash.size() > maxStashSize) {
            throw new IllegalStateException("stash exceeded maximum size");
        }
    }

    /**
     * @param label the label to hash
     * @param i the value index
     * @param tableNo the number of the table (@requires 0 or 1)
     * @param n the size of the table
     * @param key the secret key for the DPRF hash
     * @return fk(label || i || tableNo) mod n
     * @throws IOException
     */
    public static int getHash(
            final Label label, final int i, final int tableNo, final int n, final SecretKey key)
            throws IOException {
        final var toHash =
                org.bouncycastle.util.Arrays.concatenate(
                        label.label(),
                        CastingHelpers.fromIntToByteArray(i),
                        CastingHelpers.fromIntToByteArray(tableNo));
        final var result =
                CastingHelpers.fromByteArrayToHashModN(
                        DPRF.calculateFk(
                                CastingHelpers.fromByteArrayToBitInputStream(toHash),
                                key.getEncoded()),
                        n);
        return result;
    }

    /**
     * @param table one of the two tables used for the Cuckoo Hashing
     * @param hash the table index calculated with the DPRF hash
     * @param pairLabelPlaintext the (label, value) pair in plaintext to insert into the table at
     *     index hash
     * @return the evicted element if the location has been taken, null otherwise
     */
    private static PairLabelPlaintext insert(
            final PairLabelPlaintext[] table,
            final int hash,
            final PairLabelPlaintext pairLabelPlaintext) {
        PairLabelPlaintext removed = null;
        if (table[hash] != null) {
            removed = table[hash];
        }
        table[hash] = pairLabelPlaintext;
        return removed;
    }
}
