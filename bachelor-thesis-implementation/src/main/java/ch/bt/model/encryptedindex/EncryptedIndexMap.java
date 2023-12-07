package ch.bt.model.encryptedindex;

import ch.bt.model.multimap.CiphertextWithIV;
import ch.bt.model.multimap.Label;
import java.util.Map;

public record EncryptedIndexMap(Map<Label, CiphertextWithIV> map) implements EncryptedIndex {
}
