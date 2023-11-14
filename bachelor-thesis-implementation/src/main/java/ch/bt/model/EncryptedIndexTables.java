package ch.bt.model;

public class EncryptedIndexTables implements EncryptedIndex {
    private final Pair[] table1;
    private final Pair[] table2;

    public EncryptedIndexTables(final Pair[] table1, final Pair[] table2) {
        this.table1 = table1;
        this.table2 = table2;
    }

    public Pair[] getTable(final int number) {
        return number == 0 ? table1 : table2;
    }
}
