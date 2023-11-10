package ch.bt.crypto;

import java.util.List;

public class SecretKeyPair implements SecretKey {
    private final SecretKeySingle key1;
    private final SecretKeySingle key2;


    public SecretKeyPair(final SecretKeySingle key1, final SecretKeySingle key2) {
        this.key1 = key1;
        this.key2 = key2;
    }

    public SecretKeyWrapper getKey() {
        return new SecretKeyWrapper(List.of(key1, key2));
    }
}
