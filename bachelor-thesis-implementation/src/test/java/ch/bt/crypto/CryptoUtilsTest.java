package ch.bt.crypto;

import static org.junit.jupiter.api.Assertions.*;

import ch.bt.TestConfigurations;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.util.Arrays;
import java.util.Random;

@ExtendWith({TestConfigurations.class})
public class CryptoUtilsTest {

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testGenerateKeyForAES(final int securityParameter) throws GeneralSecurityException {
        final var key = CryptoUtils.generateKeyForAES(securityParameter);
        final var key2 = CryptoUtils.generateKeyForAES(securityParameter);

        // PROPERTY 1: key size must be equal to security parameter
        assertEquals(securityParameter, key.getEncoded().length * Byte.SIZE);

        // PROPERTY 2: key generation should be probabilistic
        assertNotEquals(key, key2);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getInvalidSecurityParametersForAES")
    public void testExceptionInGenerateKeyForAES(final int securityParameter) {
        Throwable exception =
                assertThrows(
                        InvalidParameterException.class,
                        () -> CryptoUtils.generateKeyForAES(securityParameter));
        assertEquals(
                "Attempt to create key with invalid key size [" + securityParameter + "]: AES",
                exception.getMessage());
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForHmac")
    public void testGenerateKeyWithHmac(final int securityParameter)
            throws GeneralSecurityException {
        final var key = CryptoUtils.generateKeyWithHMac(securityParameter);
        final var key2 = CryptoUtils.generateKeyWithHMac(securityParameter);

        // PROPERTY 1: key size must be equal to security parameter
        assertEquals(securityParameter, key.getEncoded().length * Byte.SIZE);

        // PROPERTY 2: key generation should be probabilistic
        assertNotEquals(key, key2);
    }

    @Test
    public void testCalculateSha3Digest() throws GeneralSecurityException {
        Random random = new Random();
        final int length = 256;
        final byte[] data = new byte[length];
        final byte[] data2 = new byte[length];
        random.nextBytes(data);
        random.nextBytes(data2);
        while (Arrays.equals(data, data2)) {
            random.nextBytes(data2);
        }
        final var hash1OfData = CryptoUtils.calculateSha3Digest(data);
        final var hash2OfData = CryptoUtils.calculateSha3Digest(data);
        final var hash1OfData2 = CryptoUtils.calculateSha3Digest(data2);
        final var hash1OfBothData =
                CryptoUtils.calculateSha3Digest(
                        org.bouncycastle.util.Arrays.concatenate(data, data2));

        // PROPERTY 1: hash must be deterministic
        assertArrayEquals(hash1OfData, hash2OfData);

        // PROPERTY 2: hash must be different for different data
        assertFalse(Arrays.equals(hash1OfData, hash1OfData2));

        // PROPERTY 3:  sha3 does not work as DPRF
        assertFalse(
                Arrays.equals(
                        org.bouncycastle.util.Arrays.concatenate(hash1OfData, hash1OfData2),
                        hash1OfBothData));
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForHmac")
    public void testCalculateHmac(final int securityParameter) throws GeneralSecurityException {
        final var key = CryptoUtils.generateKeyWithHMac(securityParameter);
        final var key2 = CryptoUtils.generateKeyWithHMac(securityParameter);
        Random random = new Random();
        final int length = 256;
        final byte[] data = new byte[length];
        final byte[] data2 = new byte[length];
        random.nextBytes(data);
        random.nextBytes(data2);
        while (Arrays.equals(data, data2)) {
            random.nextBytes(data2);
        }
        final var hash1OfDataWithKey = CryptoUtils.calculateHmac(key, data);
        final var hash2OfDataWithKey = CryptoUtils.calculateHmac(key, data);
        final var hash1OfDataWithKey2 = CryptoUtils.calculateHmac(key2, data);
        final var hash2OfData2WithKey = CryptoUtils.calculateHmac(key, data2);

        // PROPERTY 1: hash must be deterministic
        assertArrayEquals(hash1OfDataWithKey, hash2OfDataWithKey);

        // PROPERTY 2: hash must be different for different data
        assertFalse(Arrays.equals(hash2OfDataWithKey, hash2OfData2WithKey));

        // PROPERTY 3: hash must be different for different keys
        assertFalse(Arrays.equals(hash2OfDataWithKey, hash1OfDataWithKey2));
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testAES(final int securityParameter) throws GeneralSecurityException {
        Random random = new Random();
        final int length = 256;
        final byte[] data = new byte[length];
        final byte[] data2 = new byte[length];
        random.nextBytes(data);
        random.nextBytes(data2);
        while (Arrays.equals(data, data2)) {
            random.nextBytes(data2);
        }
        final var key = CryptoUtils.generateKeyForAES(securityParameter);
        final var key2 = CryptoUtils.generateKeyForAES(securityParameter);
        final var ciphertext1OfDataWithKey = CryptoUtils.cbcEncrypt(key, data);
        final var ciphertext2OfDataWithKey = CryptoUtils.cbcEncrypt(key, data);
        final var ciphertext1OfDataWithKey2 = CryptoUtils.cbcEncrypt(key2, data);
        final var ciphertext1OfData2WithKey = CryptoUtils.cbcEncrypt(key, data2);

        // PROPERTY 1: encryption is probabilistic
        assertNotEquals(ciphertext1OfDataWithKey, ciphertext2OfDataWithKey);

        // PROPERTY 2: encryption with different keys gives different result
        assertNotEquals(ciphertext1OfDataWithKey, ciphertext1OfDataWithKey2);

        // PROPERTY 3: encryption with different data gives different result
        assertNotEquals(ciphertext1OfDataWithKey, ciphertext1OfData2WithKey);

        // PROPERTY 4: decryption is deterministic
        assertArrayEquals(
                CryptoUtils.cbcDecrypt(key, ciphertext1OfDataWithKey),
                CryptoUtils.cbcDecrypt(key2, ciphertext1OfDataWithKey2));
    }
}
