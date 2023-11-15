package ch.bt.crypto;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class HMacHash implements Hash {
    private static final Digest DEFAULT_HASH = new SHA512Digest(CryptoServicePurpose.AUTHENTICATION);
    private final HMac hMac;
    private final KeyParameter keyParameter;

    public HMacHash(final KeyParameter keyParameter) {
        this.keyParameter = keyParameter;
        this.hMac = new HMac(DEFAULT_HASH);
        hMac.init(this.keyParameter);
    }

    public HMacHash(final KeyParameter keyParameter, final Digest hash) {
        this.keyParameter = keyParameter;
        this.hMac = new HMac(hash);
        hMac.init(this.keyParameter);
    }

    @Override
    public byte[] hash(final byte[] input) {
        hMac.update(input, 0, keyParameter.getKey().length);
        byte[] output = new byte[hMac.getMacSize()];
        hMac.doFinal(output, 0);
        return output;
    }
}
