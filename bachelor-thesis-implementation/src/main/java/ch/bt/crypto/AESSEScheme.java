package ch.bt.crypto;

import ch.bt.model.*;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.security.SecureRandom;
import java.util.*;

public class AESSEScheme implements SEScheme {
    private static final int LENGTH_INTIALISATION_VECTOR = 16;
    private final SecureRandom secureRandom;
    private final SecretKey key;
    private final Map<byte[], CipherParameters> cipherParameters = new HashMap<>();
    private PaddedBufferedBlockCipher ENCRYPTION_CIPHER;
    private PaddedBufferedBlockCipher DECRYPTION_CIPHER;

    public AESSEScheme(final SecureRandom secureRandom, final int securityParameter) {
        if (securityParameter > 256) {
            throw new IllegalArgumentException("security parameter too large");
        }
        this.secureRandom = secureRandom;
        this.key = generateKey(securityParameter);
        this.init();
    }

    public AESSEScheme(final SecureRandom secureRandom, final SecretKey key) {
        if (key instanceof SecretKeySingle
                && key.getKey().keys().get(0).getBytes().length > 256 / Byte.SIZE) {
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
        final var cipher = ENCRYPTION_CIPHER;
        final var initialisationVector = new byte[LENGTH_INTIALISATION_VECTOR];
        secureRandom.nextBytes(initialisationVector);
        final var cipherParameter =
                new ParametersWithIV(
                        new KeyParameter(key.getKey().keys().get(0).getBytes()),
                        initialisationVector);
        cipher.init(true, cipherParameter);
        final var output = new byte[cipher.getOutputSize(input.length)];
        processInput(true, input, output);
        cipherParameters.put(output, cipherParameter);
        return output;
    }

    @Override
    public byte[] decrypt(byte[] input) {
        final var cipher = DECRYPTION_CIPHER;
        final var cipherParameter = cipherParameters.get(input);
        cipher.init(false, cipherParameter);
        final var output =
                new byte[cipher.getOutputSize(input.length - LENGTH_INTIALISATION_VECTOR)];
        processInput(false, input, output);
        return output;
    }

    private void processInput(final boolean isEncryption, final byte[] input, final byte[] output) {
        final var cipher = isEncryption ? ENCRYPTION_CIPHER : DECRYPTION_CIPHER;
        final var blockSize = cipher.getBlockSize();
        final var numberOfBlocks = input.length / blockSize;
        int processedBytes = 0;
        for (int i = 0; i < numberOfBlocks; i++) {
            processedBytes +=
                    cipher.processBytes(input, i * blockSize, blockSize, output, processedBytes);
        }
        try {
            cipher.doFinal(output, processedBytes);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    public PairLabelValue encrypt(final PairLabelValue pairLabelValue) {
        return new PairLabelValue(
                new Label(encrypt(pairLabelValue.getLabel().getLabel())),
                new Value(encrypt(pairLabelValue.getValue().getValue())));
    }

    public PairLabelValue decrypt(final PairLabelValue pairLabelValue) {
        return new PairLabelValue(
                new Label(decrypt(pairLabelValue.getLabel().getLabel())),
                new Value(decrypt(pairLabelValue.getValue().getValue())));
    }
}
