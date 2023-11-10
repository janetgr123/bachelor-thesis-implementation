package ch.bt.model;

public class Value {
    private final byte[] value;

    public Value(final byte[] value){
        this.value = value;
    }

    public byte[] getValue(){
        return this.value;
    }
}