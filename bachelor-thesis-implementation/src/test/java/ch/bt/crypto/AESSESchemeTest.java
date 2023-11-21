package ch.bt.crypto;

import static org.junit.jupiter.api.Assertions.*;

import ch.bt.TestConfigurations;
import ch.bt.TestUtils;
import ch.bt.model.Plaintext;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.util.*;

@ExtendWith({TestConfigurations.class})
public class AESSESchemeTest {

    private static final Logger logger = LoggerFactory.getLogger(AESSESchemeTest.class);
    private static final Map<Integer, Plaintext> plaintexts = new HashMap<>();
    private static final Map<Integer, AESSEScheme> aesSESchemes = new HashMap<>();

    @BeforeAll
    public static void init() {
        TestUtils.getValidSecurityParametersForAES()
                .forEach(
                        securityParameter -> {
                            final var plaintext = new byte[securityParameter];
                            new Random().nextBytes(plaintext);
                            plaintexts.put(securityParameter, new Plaintext(plaintext));
                            try {
                                final var aesseScheme = new AESSEScheme(securityParameter);
                                aesSESchemes.put(securityParameter, aesseScheme);
                            } catch (GeneralSecurityException e) {
                                logger.warn(
                                        "Exception happened during AES instantiation with security parameter {}. Skip.",
                                        securityParameter);
                            }
                        });
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testCorrectness(final int securityParameter) throws GeneralSecurityException {
        final var aesseScheme = aesSESchemes.get(securityParameter);
        final var plaintext = plaintexts.get(securityParameter);
        final var ciphertext = aesseScheme.encrypt(plaintext);
        final var generatedPlaintext = aesseScheme.decrypt(ciphertext);

        // PROPERTY: Dec(K, Enc(K, m)) = m
        assertEquals(plaintext, generatedPlaintext);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testSchemeDeterminism(final int securityParameter) throws GeneralSecurityException {
        final var aesseScheme = aesSESchemes.get(securityParameter);
        final var aesseScheme2 = new AESSEScheme(securityParameter);
        final var plaintext = plaintexts.get(securityParameter);
        final var ciphertext = aesseScheme.encrypt(plaintext);
        final var ciphertext2 = aesseScheme2.encrypt(plaintext);
        final var generatedPlaintext = aesseScheme.decrypt(ciphertext);
        final var generatedPlaintext2 = aesseScheme2.decrypt(ciphertext2);

        // PROPERTY: encrypting and decrypting the same data gives again the same data independent
        // of the scheme instance
        assertEquals(generatedPlaintext, generatedPlaintext2);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testEncryptionIsProbabilistic(final int securityParameter)
            throws GeneralSecurityException {
        final var aesseScheme = aesSESchemes.get(securityParameter);
        final var plaintext = plaintexts.get(securityParameter);
        final var ciphertext = aesseScheme.encrypt(plaintext);
        final var ciphertext2 = aesseScheme.encrypt(plaintext);

        // PROPERTY: the encryption is probabilistic and results in different iv's and ciphertexts
        assertFalse(Arrays.equals(ciphertext.iv(), ciphertext2.iv()));
        assertFalse(Arrays.equals(ciphertext.data(), ciphertext2.data()));
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getInvalidSecurityParametersForAES")
    public void testException(final int securityParameter) {

        // PROPERTY: key sizes greater than 256 bits are invalid for AES
        Throwable exception =
                assertThrows(
                        IllegalArgumentException.class, () -> new AESSEScheme(securityParameter));
        assertEquals(
                "Attempt to create key with invalid key size [" + securityParameter + "]: AES",
                exception.getMessage());
    }
}
