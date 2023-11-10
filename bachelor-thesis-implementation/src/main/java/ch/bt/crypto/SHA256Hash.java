package ch.bt.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.KeyParameter;

public class SHA256Hash implements Hash {
    private final SHA256Digest hash;
    private final KeyParameter keyParameter;

    public SHA256Hash(final KeyParameter keyParameter){
        this.keyParameter = keyParameter;
        this.hash = new SHA256Digest();
    }

    @Override
    public byte[] hash(final byte[] input) {
        hash.update(input, 0, input.length);
        return input;
    }
}
