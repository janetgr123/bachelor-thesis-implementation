package ch.bt.crypto;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

public class KeyGenerator {
    private final CipherKeyGenerator keyGenerator = new CipherKeyGenerator();

    public KeyGenerator(final SecureRandom secureRandom, final int securityParameter){
        keyGenerator.init(new KeyGenerationParameters(secureRandom, securityParameter));
    }

    public SecretKeySingle generateKey(){
        return new SecretKeySingle(keyGenerator.generateKey());
    }
}
