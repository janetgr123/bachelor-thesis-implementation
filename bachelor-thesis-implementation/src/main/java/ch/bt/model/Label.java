package ch.bt.model;

public class Label {
    private final byte[] label;

    public Label(final byte[] label){
        this.label = label;
    }

    public byte[] getLabel(){
        return this.label;
    }
}
