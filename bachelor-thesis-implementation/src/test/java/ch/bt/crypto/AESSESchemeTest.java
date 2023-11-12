package ch.bt.crypto;

import ch.bt.emm.AESSEScheme;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.SecureRandom;
import java.util.*;

public class AESSESchemeTest {

    @ParameterizedTest
    @ValueSource(ints = {128, 256})
    public void testCorrectness(final int securityParameter) {
        AESSEScheme aesseScheme = new AESSEScheme(new SecureRandom(), securityParameter);
        final byte[] plaintext = new byte[securityParameter];
        new Random().nextBytes(plaintext);
        final var ciphertext = aesseScheme.encrypt(plaintext);
        final var generatedPlaintext = aesseScheme.decrypt(ciphertext);
        assertTrue(Arrays.equals(plaintext, generatedPlaintext));
    }

    @ParameterizedTest
    @ValueSource(ints = {128, 256})
    public void testEncryptionIsProbabilistic(final int securityParameter) {
        AESSEScheme aesseScheme = new AESSEScheme(new SecureRandom(), securityParameter);
        final byte[] plaintext = new byte[securityParameter];
        new Random().nextBytes(plaintext);
        final var ciphertext = aesseScheme.encrypt(plaintext);
        final var ciphertext2 = aesseScheme.encrypt(plaintext);
        assertFalse(Arrays.equals(ciphertext, ciphertext2));
    }

    @ParameterizedTest
    @ValueSource(ints = {512, 1024})
    public void testException(final int securityParameter) {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> new AESSEScheme(new SecureRandom(), securityParameter));
        assertEquals("security parameter too large", exception.getMessage());
    }
}
