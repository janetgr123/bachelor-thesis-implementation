package ch.bt.cuckoHashing;

import ch.bt.crypto.CastingHelpers;
import ch.bt.crypto.DPRF;
import ch.bt.emm.dpVolumeHiding.DPVolumeHidingEMMUtils;
import ch.bt.model.multimap.Ciphertext;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.PairLabelNumberValues;
import ch.bt.model.multimap.Plaintext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

import javax.crypto.SecretKey;

/**
 * This class implements the Cuckoo Hashing with Stash for the counter table from <a
 * href="https://doi.org/10.1145/2508859.2516668">Kirsch et al.</a>.
 *
 * @author Janet Greutmann
 */
public class CuckooHashingCT {
    private static final Logger logger = LoggerFactory.getLogger(DPVolumeHidingEMMUtils.class);

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
    public static void doCuckooHashingWithStashCT(
            final int maxNumberOfEvictions,
            final PairLabelNumberValues[] table1,
            final PairLabelNumberValues[] table2,
            final Map<Label, Set<Plaintext>> multiMap,
            final Stack<Ciphertext> stash,
            final int tableSize,
            final SecretKey key)
            throws IOException {
        final var labels = multiMap.keySet();

        /*
         * Cuckoo Hashing process
         */
        int evictionCounter = 0;
        for (final var label : labels) {
            final var numberOfValues = multiMap.get(label).size();
            PairLabelNumberValues toInsert = new PairLabelNumberValues(label, numberOfValues);
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
                logger.debug("Inserting in table 1: {}", toInsert);
                toInsert = insert(table1, getHashCT(toInsert.label(), 0, tableSize, key), toInsert);

                /*
                 * if an element is evicted, try table 2
                 */
                if (toInsert != null) {
                    logger.debug("COLLISION! Evict from table 1: {}", toInsert);
                    logger.debug("Inserting in table 2: {}", toInsert);
                    evictionCounter++;
                    toInsert =
                            insert(
                                    table2,
                                    getHashCT(toInsert.label(), 1, tableSize, key),
                                    toInsert);

                    /*
                     * if an element is evicted, try table 1 again in the next loop round
                     */
                    if (toInsert != null) {
                        logger.debug("COLLISION! Evict from table 2: {}", toInsert);
                        evictionCounter++;
                        firstTime = false;
                    }
                }
            }

            /*
             * number of evictions is reached, the evicted element is put onto the stash
             */
            if (toInsert != null) {
                logger.debug("Could not insert element. Putting onto stash: {}", toInsert);
                stash.add(toInsert);
            }
        }

        if (stash.size() > maxStashSize) {
            throw new IllegalStateException("stash exceeded maximum size");
        }
    }

    /**
     * @param label the label to hash
     * @param tableNo the number of the table (@requires 0 or 1)
     * @param n the size of the table
     * @param key the secret key for the DPRF hash
     * @return fk(CT || label || tableNo) mod n
     * @throws IOException
     */
    public static int getHashCT(
            final Label label, final int tableNo, final int n, final SecretKey key)
            throws IOException {
        final var toHash =
                org.bouncycastle.util.Arrays.concatenate(
                        CastingHelpers.fromStringToByteArray("CT"),
                        label.label(),
                        CastingHelpers.fromIntToByteArray(tableNo));
        final var result =
                CastingHelpers.fromByteArrayToHashModN(
                        DPRF.calculateFk(
                                CastingHelpers.fromByteArrayToBitInputStream(toHash),
                                key.getEncoded()),
                        n);
        logger.info("Hashing element {}. The hash evaluates to {}.", toHash, result);
        return result;
    }

    /**
     * @param table one of the two tables used for the Cuckoo Hashing
     * @param hash the table index calculated with the DPRF hash
     * @param pairLabelNumberValues the (label, number of values) pair in plaintext to insert into
     *     the table at index hash
     * @return the evicted element if the location has been taken, null otherwise
     */
    private static PairLabelNumberValues insert(
            final PairLabelNumberValues[] table,
            final int hash,
            final PairLabelNumberValues pairLabelNumberValues) {
        PairLabelNumberValues removed = null;
        if (table[hash] != null) {
            removed = table[hash];
        }
        table[hash] = pairLabelNumberValues;
        return removed;
    }
}
