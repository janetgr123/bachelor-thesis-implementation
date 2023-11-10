package ch.bt.model;

public class Label {
    private byte[] label;

    public Label(final byte[] label){
        this.label = label;
    }

    public byte[] getLabel(){
        return this.label;
    }
}
