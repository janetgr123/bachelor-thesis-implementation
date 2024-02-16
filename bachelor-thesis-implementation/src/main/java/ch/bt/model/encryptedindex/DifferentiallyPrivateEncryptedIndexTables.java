package ch.bt.model.encryptedindex;

/**
 * This record encapsulates the encrypted index of the scheme type {@link ch.bt.emm.TwoRoundEMM}
 *
 * @param encryptedIndex the encrypted index of the value tables
 * @param encryptedIndexCT the encrypted index of the counter tables
 * @author Janet Greutmann
 */
public record DifferentiallyPrivateEncryptedIndexTables(
        EncryptedIndex encryptedIndex, EncryptedIndex encryptedIndexCT) implements EncryptedIndex {
    /**
     * @return the size of the encrypted index consisting of the sum of the sizes of the underlying
     *     indices
     */
    @Override
    public int size() {
        return (encryptedIndex == null ? 0 : encryptedIndex.size())
                + (encryptedIndexCT == null ? 0 : encryptedIndexCT.size());
    }
}
