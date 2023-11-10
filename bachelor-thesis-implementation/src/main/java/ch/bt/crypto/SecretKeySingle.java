package ch.bt.crypto;

import java.util.List;

public class SecretKeySingle implements SecretKey {
    private final byte[] key;

    public SecretKeySingle(final byte[] key) {
        this.key = key;
    }

    @Override
    public SecretKeyWrapper getKey() {
        return new SecretKeyWrapper(List.of(this));
    }

    public byte[] getBytes(){
        return this.key;
    }
}
