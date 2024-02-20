package ch.bt.model.encryptedindex;

import ch.bt.model.multimap.PairLabelCiphertext;

/**
 * This class encapsulates the encrypted index of the scheme type {@link ch.bt.emm.EMM} and {@link
 * ch.bt.emm.TwoRoundEMM}
 *
 * @author Janet Greutmann
 */
public class EncryptedIndexTables implements EncryptedIndex {
    /** table 1 for Cuckoo Hashing */
    private final PairLabelCiphertext[] table1;

    /** table 2 for Cuckoo Hashing */
    private final PairLabelCiphertext[] table2;

    public EncryptedIndexTables(
            final PairLabelCiphertext[] table1, final PairLabelCiphertext[] table2) {
        this.table1 = table1;
        this.table2 = table2;
    }

    /**
     * @param number the table number (@requires 0 or 1)
     * @return table1 if number is 0, table2 otherwise
     */
    public PairLabelCiphertext[] getTable(final int number) {
        return number == 0 ? table1 : table2;
    }

    /**
     * @return the size of the two tables
     */
    @Override
    public int size() {
        return (table1.length + table2.length)
                * (32 * 2); // AES generates label-value pair of each 32 bytes
    }
}
