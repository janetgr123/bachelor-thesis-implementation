package ch.bt.model.encryptedindex;

import java.util.List;

/**
 * This record encapsulates the encrypted index of the scheme type {@link ch.bt.emm.basic.BasicEMM}
 *
 * @param list the encrypted index as a list
 * @author Janet Greutmann
 */
public record EncryptedIndexTable(List<byte[]> list) implements EncryptedIndex {
    /**
     * @return the size of the multimap
     */
    @Override
    public int size() {
        return list.size();
    }
}
