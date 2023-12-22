package ch.bt.model.encryptedindex;

public record DifferentiallyPrivateEncryptedIndexTables(
        EncryptedIndex encryptedIndex, EncryptedIndex encryptedIndexCT) implements EncryptedIndex {
    @Override
    public int size() {
        return encryptedIndex.size() + encryptedIndexCT.size();
    }
}
