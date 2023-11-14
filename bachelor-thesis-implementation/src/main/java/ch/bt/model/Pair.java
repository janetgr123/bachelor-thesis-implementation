package ch.bt.model;

import ch.bt.crypto.SEScheme;

public class Pair {
    private final Label label;
    private final Value value;

    public Pair(Label label, Value value) {
        this.label = label;
        this.value = value;
    }

    public Label getLabel() {
        return label;
    }

    public Value getValue() {
        return value;
    }

    public Pair encrypt(final SEScheme scheme) {
        return new Pair(new EncryptedLabel(scheme.encrypt(label.getLabel())), new EncryptedValue(scheme.encrypt(value.getValue())));
    }

    public Pair decrypt(final SEScheme scheme) {
        return new Pair(new PlaintextLabel(scheme.decrypt(label.getLabel())), new PlaintextValue(scheme.decrypt(value.getValue())));
    }
}
