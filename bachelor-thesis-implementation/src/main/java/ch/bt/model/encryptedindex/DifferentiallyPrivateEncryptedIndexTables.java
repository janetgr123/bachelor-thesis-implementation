package ch.bt.model.encryptedindex;

import ch.bt.model.PairLabelCiphertext;

public class DifferentiallyPrivateEncryptedIndexTables implements EncryptedIndex {
    private final PairLabelCiphertext[] counterTable1;
    private final PairLabelCiphertext[] counterTable2;

    private final EncryptedIndex encryptedIndexTables;

    public DifferentiallyPrivateEncryptedIndexTables(
            EncryptedIndex encryptedIndexTables,
            final PairLabelCiphertext[] counterTable1,
            final PairLabelCiphertext[] counterTable2) {
        this.encryptedIndexTables = encryptedIndexTables;
        this.counterTable1 = counterTable1;
        this.counterTable2 = counterTable2;
    }

    public PairLabelCiphertext[] getCounterTable(final int number) {
        return number == 0 ? counterTable1 : counterTable2;
    }

    public EncryptedIndex getEncryptedIndexTables() {
        return encryptedIndexTables;
    }
}
