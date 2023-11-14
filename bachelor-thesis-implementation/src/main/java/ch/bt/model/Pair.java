package ch.bt.model;


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
}
