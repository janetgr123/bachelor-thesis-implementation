package ch.bt.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;

public class SHA256Hash implements Hash {
    private final SHA256Digest hash;

    public SHA256Hash(){
        this.hash = new SHA256Digest();
    }

    @Override
    public byte[] hash(final byte[] input) {
        hash.update(input, 0, input.length);
        return input;
    }
}
