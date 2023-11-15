package ch.bt.model;

public class DifferentiallyPrivateEncryptedIndexTables implements EncryptedIndex {
    private final PairLabelNumberValues[] counterTable1;
    private final PairLabelNumberValues[] counterTable2;

    private final EncryptedIndex encryptedIndexTables;

    public DifferentiallyPrivateEncryptedIndexTables(
            EncryptedIndex encryptedIndexTables,
            final PairLabelNumberValues[] counterTable1,
            final PairLabelNumberValues[] counterTable2) {
        this.encryptedIndexTables = encryptedIndexTables;
        this.counterTable1 = counterTable1;
        this.counterTable2 = counterTable2;
    }

    public PairLabelNumberValues[] getCounterTable(final int number) {
        return number == 0 ? counterTable1 : counterTable2;
    }

    public EncryptedIndex getEncryptedIndexTables() {
        return encryptedIndexTables;
    }
}
