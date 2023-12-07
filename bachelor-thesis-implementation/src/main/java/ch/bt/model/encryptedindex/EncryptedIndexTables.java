package ch.bt.model.encryptedindex;

import ch.bt.model.multimap.PairLabelCiphertext;
public class EncryptedIndexTables implements EncryptedIndex {
    private final PairLabelCiphertext[] table1;
    private final PairLabelCiphertext[] table2;

    public EncryptedIndexTables(final PairLabelCiphertext[] table1, final PairLabelCiphertext[] table2) {
        this.table1 = table1;
        this.table2 = table2;
    }

    public PairLabelCiphertext[] getTable(final int number) {
        return number == 0 ? table1 : table2;
    }
}
