package ch.bt.emm;

import static org.junit.jupiter.api.Assertions.*;

import ch.bt.TestConfigurations;
import ch.bt.TestUtils;
import ch.bt.model.Label;
import ch.bt.model.Plaintext;
import ch.bt.model.encryptedindex.EncryptedIndexTables;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

// TODO: FIX!!!!!
@Disabled
@ExtendWith({TestConfigurations.class})
public class VolumeHidingEMMOptimisedTest {

    private static final Map<Integer, VolumeHidingEMMOptimised> volumeHidingEMMOptimised = new HashMap<>();

    private static final Map<Label, Set<Plaintext>> multiMap = TestUtils.multimap;

    private static final Label searchLabel = TestUtils.searchLabel;

    @BeforeAll
    public static void init() {
        TestUtils.getValidSecurityParametersForAES()
                .forEach(
                        securityParameter -> {
                            try {
                                final var emm =
                                        new VolumeHidingEMMOptimised(securityParameter, TestUtils.ALPHA);
                                volumeHidingEMMOptimised.put(securityParameter, emm);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testCorrectness(final int securityParameter) throws GeneralSecurityException, IOException {
        final var volumeHidingEMM = volumeHidingEMMOptimised.get(securityParameter);
        final var encryptedIndex = volumeHidingEMM.buildIndex(multiMap);
        final var searchToken = volumeHidingEMM.trapdoor(searchLabel);
        final var ciphertexts = volumeHidingEMM.search(searchToken, encryptedIndex);
        final var values = volumeHidingEMM.result(ciphertexts).stream().sorted().toList();
        final var expectedValues = multiMap.get(searchLabel).stream().sorted().toList();

        // PROPERTY: Result(Search(Trapdoor(label), BuildIndex(multiMap))) = multiMap[label]
        assertEquals(expectedValues, values);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testBuildIndex(final int securityParameter) throws GeneralSecurityException {
        final var volumeHidingEMM = volumeHidingEMMOptimised.get(securityParameter);
        final var table11 =
                ((EncryptedIndexTables) volumeHidingEMM.buildIndex(multiMap)).getTable(0);
        final var table12 =
                ((EncryptedIndexTables) volumeHidingEMM.buildIndex(multiMap)).getTable(1);
        final var table21 =
                ((EncryptedIndexTables) volumeHidingEMM.buildIndex(multiMap)).getTable(0);
        final var table22 =
                ((EncryptedIndexTables) volumeHidingEMM.buildIndex(multiMap)).getTable(1);
        final var labels =
                VolumeHidingEMMUtils.getDecryptedLabels(volumeHidingEMM, table11, table12);
        final var labels2 =
                VolumeHidingEMMUtils.getDecryptedLabels(volumeHidingEMM, table21, table22);

        // PROPERTY 1:  Encrypted labels for fixed EMM scheme and multimap are deterministic.
        // REASON:      Construction uses Cuckoo Hashing with stash with SHA3 hashes that are
        //              deterministic.
        assertEquals(labels, labels2);

        final var values =
                VolumeHidingEMMUtils.getDecryptedValues(volumeHidingEMM, table11, table12);
        final var values2 =
                VolumeHidingEMMUtils.getDecryptedValues(volumeHidingEMM, table21, table22);

        // PROPERTY 2:  Encrypted values for fixed EMM scheme and multimap decrypt to identical
        //              values.
        // REASON:      AES scheme decryption is deterministic.
        assertEquals(values, values2);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getInvalidSecurityParametersForAES")
    public void testKeyTooLongForSE(final int securityParameter) {

        // PROPERTY:    EMM scheme uses AES scheme and therefore keys greater than 256 bits are
        //              invalid.
        Throwable exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> new VolumeHidingEMMOptimised(securityParameter, TestUtils.ALPHA));
        assertEquals(
                "Attempt to create key with invalid key size [" + securityParameter + "]: AES",
                exception.getMessage());
    }
}
