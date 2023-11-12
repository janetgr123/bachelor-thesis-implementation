package ch.bt.crypto;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

public class HKDFDerivator implements KeyDerivator {
    private final HKDFBytesGenerator hkdfBytesGenerator;

    public HKDFDerivator(final int securityParameter){
        final var hash = switch(securityParameter){
            case 256 -> new SHA256Digest();
            case 512 -> new SHA512Digest();
            default -> throw new IllegalArgumentException("security parameter doesn't match hash");
        };
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
