package ch.bt.crypto;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

public class HKDFDerivator implements KeyDerivator {
    private final HKDFBytesGenerator hkdfBytesGenerator;
    private static final Digest DEFAULT_HASH = new SHA256Digest();

    public HKDFDerivator(){
        this.hkdfBytesGenerator = new HKDFBytesGenerator(DEFAULT_HASH);
    }

    public HKDFDerivator(Digest hash){
        this.hkdfBytesGenerator = new HKDFBytesGenerator(hash);
    }

    @Override
    public SecretKeySingle deriveKeyFrom(SecretKeySingle masterKey, final byte[] salt) {
        byte[] key = masterKey.getBytes();
        hkdfBytesGenerator.init(HKDFParameters.defaultParameters(key));
        final var derivedKey = hkdfBytesGenerator.extractPRK(salt, key);
        return new SecretKeySingle(derivedKey);
    }
}
