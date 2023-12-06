package ch.bt.emm;

import static org.junit.jupiter.api.Assertions.*;

import ch.bt.TestConfigurationsWithDB;
import ch.bt.TestUtils;
import ch.bt.emm.basic.BasicEMM;
import ch.bt.model.encryptedindex.EncryptedIndexMap;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.util.*;

@ExtendWith({TestConfigurationsWithDB.class})
public class BasicEMMTest {
    private static final Map<Integer, BasicEMM> basicEMMMs = new HashMap<>();

    private static Map<Label, Set<Plaintext>> multimap;

    private static Label searchLabel;

    @BeforeAll
    public static void init() {
        multimap = TestUtils.multimap;
        searchLabel = TestUtils.searchLabel;
        TestUtils.getValidSecurityParametersForAES()
                .forEach(
                        securityParameter -> {
                            try {
                                final var emm = new BasicEMM(securityParameter);
                                basicEMMMs.put(securityParameter, emm);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testCorrectness(final int securityParameter) throws GeneralSecurityException {
        final var basicEMM = basicEMMMs.get(securityParameter);
        final var encryptedIndex = basicEMM.buildIndex(multimap);
        final var searchToken = basicEMM.trapdoor(searchLabel);
        final var ciphertexts = basicEMM.search(searchToken, encryptedIndex);
        final var values = basicEMM.result(ciphertexts, searchLabel).stream().sorted().toList();
        final var expectedValues = multimap.get(searchLabel).stream().sorted().toList();

        // PROPERTY: Result(Search(Trapdoor(label), BuildIndex(multiMap))) = multiMap[label]
        assertEquals(values, expectedValues);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testBuildIndex(final int securityParameter) throws GeneralSecurityException {
        final var basicEMM = basicEMMMs.get(securityParameter);
        final var encryptedIndex = ((EncryptedIndexMap) basicEMM.buildIndex(multimap)).map();
        final var encryptedIndex2 = ((EncryptedIndexMap) basicEMM.buildIndex(multimap)).map();
        final var labels = encryptedIndex.keySet().stream().sorted().toList();
        final var labels2 = encryptedIndex2.keySet().stream().sorted().toList();

        // PROPERTY 1:  Encrypted labels for fixed EMM scheme and multimap are deterministic.
        // REASON:      Construction uses HMAC and SHA3 hashes that are deterministic.
        assertEquals(labels, labels2);

        final var values = encryptedIndex.values().stream().sorted().toList();
        final var values2 = encryptedIndex2.values().stream().sorted().toList();

        // PROPERTY 2:  Encrypted values for fixed EMM scheme and multimap are probabilistic.
        // REASON:      AES scheme encryption is probabilistic.
        assertNotEquals(values, values2);

        final var decryptedValues =
                encryptedIndex.values().stream()
                        .map(
                                el -> {
                                    try {
                                        return basicEMM.getSeScheme().decrypt(el);
                                    } catch (GeneralSecurityException e) {
                                        throw new RuntimeException(e);
                                    }
                                })
                        .sorted()
                        .toList();
        final var decryptedValues2 =
                encryptedIndex2.values().stream()
                        .map(
                                el -> {
                                    try {
                                        return basicEMM.getSeScheme().decrypt(el);
                                    } catch (GeneralSecurityException e) {
                                        throw new RuntimeException(e);
                                    }
                                })
                        .sorted()
                        .toList();

        // PROPERTY 3:  Encrypted values for fixed EMM scheme and multimap decrypt to identical
        //              values.
        // REASON:      AES scheme decryption is deterministic.
        assertEquals(decryptedValues, decryptedValues2);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getInvalidSecurityParametersForAES")
    public void testKeyTooLongForSE(final int securityParameter) {

        // PROPERTY:    EMM scheme uses AES scheme and therefore keys greater than 256 bits are
        //              invalid.
        Throwable exception =
                assertThrows(
                        InvalidParameterException.class, () -> new BasicEMM(securityParameter));
        assertEquals(
                "Attempt to create key with invalid key size [" + securityParameter + "]: AES",
                exception.getMessage());
    }
}
