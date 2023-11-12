package ch.bt.crypto;

import org.bouncycastle.crypto.digests.SHA512Digest;

public class SHA512Hash implements Hash {
    private final SHA512Digest hash;

    public SHA512Hash(){
        this.hash = new SHA512Digest();
    }

    @Override
    public byte[] hash(final byte[] input) {
        hash.update(input, 0, input.length);
        byte[] output = new byte[hash.getDigestSize()];
        hash.doFinal(output, 0);
        return output;
    }
}
