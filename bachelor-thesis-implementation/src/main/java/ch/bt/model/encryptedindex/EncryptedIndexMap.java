package ch.bt.model.encryptedindex;

import ch.bt.model.CiphertextWithIV;
import ch.bt.model.Label;
import java.util.Map;

public record EncryptedIndexMap(Map<Label, CiphertextWithIV> map) implements EncryptedIndex {
}
