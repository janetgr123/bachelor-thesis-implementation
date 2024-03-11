package ch.bt.model.encryptedindex;

import ch.bt.model.multimap.Ciphertext;
import ch.bt.model.multimap.Label;

import java.util.Map;

/**
 * This record encapsulates the encrypted index of the scheme type {@link ch.bt.emm.basic.BasicEMM}
 *
 * @param map the encrypted index as a multimap
 * @author Janet Greutmann
 */
public record LookupTable(Map<Label, Ciphertext> map) implements EncryptedIndex {
    /**
     * @return the size of the multimap
     */
    @Override
    public int size() {
        return map.size() * (32 + 32); // label prf SHA256, value AES encrypted to 32 bytes
    }
}
