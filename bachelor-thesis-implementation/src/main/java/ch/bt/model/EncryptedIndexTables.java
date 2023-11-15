package ch.bt.model;

public class EncryptedIndexTables implements EncryptedIndex {
    private final PairLabelValue[] table1;
    private final PairLabelValue[] table2;

    public EncryptedIndexTables(final PairLabelValue[] table1, final PairLabelValue[] table2) {
        this.table1 = table1;
        this.table2 = table2;
    }

    public PairLabelValue[] getTable(final int number) {
        return number == 0 ? table1 : table2;
    }
}
