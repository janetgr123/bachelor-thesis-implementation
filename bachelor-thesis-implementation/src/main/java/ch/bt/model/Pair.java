package ch.bt.model;

import org.apache.commons.lang3.builder.ToStringBuilder;

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

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("label", label).append("value", value).toString();
    }
}
