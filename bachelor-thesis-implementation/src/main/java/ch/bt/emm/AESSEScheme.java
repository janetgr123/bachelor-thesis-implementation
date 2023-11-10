package ch.bt.emm;

import ch.bt.crypto.KeyGenerator;
import ch.bt.crypto.SEScheme;
import ch.bt.crypto.SecretKey;
import ch.bt.crypto.SecretKeySingle;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.SecureRandom;

public class AESSEScheme implements SEScheme {

    private static final BlockCipher ENCRYPTION_CIPHER = new AESFastEngine();
    private static final BlockCipher DECRYPTION_CIPHER = new AESFastEngine();

    private final SecureRandom secureRandom;

    private final SecretKey key;

    public AESSEScheme(final SecureRandom secureRandom, final int securityParameter) {
        this.secureRandom = secureRandom;
        this.key = generateKey(securityParameter);
        if (key instanceof SecretKeySingle) {
            this.init(this.key.getKey().getKeys().get(0).getBytes());
        }
    }

    public AESSEScheme(final SecureRandom secureRandom, final SecretKey key) {
        this.secureRandom = secureRandom;
        this.key = key;
        if (key instanceof SecretKeySingle) {
            this.init(this.key.getKey().getKeys().get(0).getBytes());
        }
    }

    public void init(byte[] key) {
        ENCRYPTION_CIPHER.init(true, new KeyParameter(key));
        DECRYPTION_CIPHER.init(false, new KeyParameter(key));
    }

    @Override
    public SecretKey generateKey(final int securityParameter) {
        return new KeyGenerator(secureRandom, securityParameter).generateKey();
    }

    @Override
    public byte[] encrypt(byte[] input) {
        byte[] output = new byte[input.length];
        final var blockSize = ENCRYPTION_CIPHER.getBlockSize();
        final var numberOfBlocks = input.length / blockSize;
        for (int i = 0; i < numberOfBlocks; ++i) {
            ENCRYPTION_CIPHER.processBlock(input, i * blockSize, output, i * blockSize);
        }
        return output;
    }

    @Override
    public byte[] decrypt(byte[] input) {
        byte[] output = new byte[input.length];
        final var blockSize = DECRYPTION_CIPHER.getBlockSize();
        final var numberOfBlocks = input.length / blockSize;
        for (int i = 0; i < numberOfBlocks; ++i) {
            DECRYPTION_CIPHER.processBlock(input, i * blockSize, output, i * blockSize);
        }
        return output;
    }
}
