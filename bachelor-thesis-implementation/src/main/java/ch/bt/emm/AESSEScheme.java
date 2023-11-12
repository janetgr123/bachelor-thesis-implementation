package ch.bt.emm;

import ch.bt.crypto.KeyGenerator;
import ch.bt.crypto.SEScheme;
import ch.bt.crypto.SecretKey;
import ch.bt.crypto.SecretKeySingle;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.security.SecureRandom;

public class AESSEScheme implements SEScheme {
    private PaddedBufferedBlockCipher ENCRYPTION_CIPHER;
    private PaddedBufferedBlockCipher DECRYPTION_CIPHER;
    private final SecureRandom secureRandom;

    private byte[] initialisationVector = new byte[16];

    private final SecretKey key;

    private CipherParameters cipherParameters;


    public AESSEScheme(final SecureRandom secureRandom, final int securityParameter) {
        if (securityParameter > 256) {
            throw new IllegalArgumentException("security parameter too large");
        }
        this.secureRandom = secureRandom;
        this.key = generateKey(securityParameter);
        this.init();
    }

    public AESSEScheme(final SecureRandom secureRandom, final SecretKey key) {
        if (key instanceof SecretKeySingle && key.getKey().keys().get(0).getBytes().length > 256) {
            throw new IllegalArgumentException("security parameter too large");
        }
        this.secureRandom = secureRandom;
        this.key = key;
        this.init();
    }

    public void init() {
        BlockCipher blockCipher = new AESEngine();
        CBCBlockCipher cipher = new CBCBlockCipher(blockCipher);
        ENCRYPTION_CIPHER = new PaddedBufferedBlockCipher(cipher);
        DECRYPTION_CIPHER = new PaddedBufferedBlockCipher(cipher);
    }

    @Override
    public SecretKey generateKey(final int securityParameter) {
        return new KeyGenerator(secureRandom, securityParameter).generateKey();
    }

    @Override
    public byte[] encrypt(byte[] input) {
        secureRandom.nextBytes(initialisationVector);
        cipherParameters = new ParametersWithIV(new KeyParameter(key.getKey().keys().get(0).getBytes()), initialisationVector);
        return processInput(true, input);
    }

    @Override
    public byte[] decrypt(byte[] input) {
        return processInput(false, input);
    }

    private byte[] processInput(final boolean isEncryption, final byte[] input) {
        PaddedBufferedBlockCipher cipher;
        int outputLengthReduction;
        if (isEncryption) {
            cipher = ENCRYPTION_CIPHER;
            outputLengthReduction = 0;
        } else {
            cipher = DECRYPTION_CIPHER;
            outputLengthReduction = initialisationVector.length;
        }
        cipher.init(isEncryption, cipherParameters);
        byte[] output = new byte[cipher.getOutputSize(input.length - outputLengthReduction)];
        final var blockSize = cipher.getBlockSize();
        final var numberOfBlocks = input.length / blockSize;
        int processedBytes = 0;
        for (int i = 0; i < numberOfBlocks; i++) {
            processedBytes += cipher.processBytes(input, i * blockSize, blockSize, output, processedBytes);
        }
        try {
            cipher.doFinal(output, processedBytes);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
        return output;
    }


}
