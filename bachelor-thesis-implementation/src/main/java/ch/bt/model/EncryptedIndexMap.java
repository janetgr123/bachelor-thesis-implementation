package ch.bt.model;

import java.util.Map;

public record EncryptedIndexMap(Map<Label, Value> map) implements EncryptedIndex {
}
