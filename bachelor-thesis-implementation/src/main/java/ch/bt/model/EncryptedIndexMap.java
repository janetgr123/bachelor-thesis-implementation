package ch.bt.model;

import java.util.Map;

public class EncryptedIndexMap implements EncryptedIndex {
    private final Map<Label, Value> map;

    public EncryptedIndexMap(final Map<Label, Value> map) {
        this.map = map;
    }

    public Map<Label, Value> getMap() {
        return map;
    }
}
