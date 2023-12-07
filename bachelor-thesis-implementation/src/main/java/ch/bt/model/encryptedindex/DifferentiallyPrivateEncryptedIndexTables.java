package ch.bt.model.encryptedindex;

public record DifferentiallyPrivateEncryptedIndexTables(
        EncryptedIndex encryptedIndex, EncryptedIndex encryptedIndexCT) implements EncryptedIndex {}
