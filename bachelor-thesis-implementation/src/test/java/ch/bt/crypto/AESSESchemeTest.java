package ch.bt.crypto;

import ch.bt.emm.AESSEScheme;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Stream;

public class AESSESchemeTest {
    private final static List<Integer> VALID_SECURITY_PARAMETERS = List.of(128, 256);

    private final static List<Integer> INVALID_SECURITY_PARAMETERS = List.of(512, 1024);
    private final static Map<Integer, SecretKey> keys = new HashMap<>();
    private final static Map<Integer, byte[]> plaintexts = new HashMap<>();
    private final static Map<Integer, AESSEScheme> aesSESchemes = new HashMap<>();

    @BeforeAll
    public static void init() {
        VALID_SECURITY_PARAMETERS.forEach(securityParameter -> {
                    final KeyGenerator keyGenerator = new KeyGenerator(new SecureRandom(), securityParameter);
                    final var key = keyGenerator.generateKey();
                    keys.put(securityParameter, key);
                    final var plaintext = new byte[securityParameter];
                    new Random().nextBytes(plaintext);
                    plaintexts.put(securityParameter, plaintext);
                    final var aesseScheme = new AESSEScheme(new SecureRandom(), key);
                    aesSESchemes.put(securityParameter, aesseScheme);
                }
        );

    }

    private static Stream<Integer> getValidSecurityParameters() {
        return VALID_SECURITY_PARAMETERS.stream();
    }

    private static Stream<Integer> getInvalidSecurityParameters() {
        return INVALID_SECURITY_PARAMETERS.stream();
    }

    @ParameterizedTest
    @MethodSource("getValidSecurityParameters")
    public void testCorrectness(final int securityParameter) {
        final var aesseScheme = aesSESchemes.get(securityParameter);
        final var plaintext = plaintexts.get(securityParameter);
        final var ciphertext = aesseScheme.encrypt(plaintext);
        final var generatedPlaintext = aesseScheme.decrypt(ciphertext);
        assertArrayEquals(plaintext, generatedPlaintext);
    }

    @ParameterizedTest
    @MethodSource("getValidSecurityParameters")
    public void testEncryptionIsProbabilistic(final int securityParameter) {
        final var aesseScheme = aesSESchemes.get(securityParameter);
        final var plaintext = plaintexts.get(securityParameter);
        final var ciphertext = aesseScheme.encrypt(plaintext);
        final var ciphertext2 = aesseScheme.encrypt(plaintext);
        assertFalse(Arrays.equals(ciphertext, ciphertext2));
    }

    @ParameterizedTest
    @MethodSource("getInvalidSecurityParameters")
    public void testException(final int securityParameter) {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> new AESSEScheme(new SecureRandom(), securityParameter));
        assertEquals("security parameter too large", exception.getMessage());
    }
}
