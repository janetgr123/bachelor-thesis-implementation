package ch.bt.emm;

import static org.junit.jupiter.api.Assertions.*;

import ch.bt.TestConfigurations;
import ch.bt.TestUtils;
import ch.bt.model.encryptedindex.DifferentiallyPrivateEncryptedIndexTables;
import ch.bt.model.encryptedindex.EncryptedIndexTables;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.GeneralSecurityException;
import java.util.*;

@ExtendWith({TestConfigurations.class})
public class DifferentiallyPrivateVolumeHidingEMMTest {
    private static final int ALPHA = 2;
    private static final double EPSILON = 0.2;
    private static final Map<Integer, DifferentiallyPrivateVolumeHidingEMM>
            differentiallyPrivateVolumeHidingEMMs = new HashMap<>();

    @BeforeAll
    public static void init() {
        TestUtils.getValidSecurityParametersForAES()
                .forEach(
                        securityParameter -> {
                            try {
                                final var emm =
                                        new DifferentiallyPrivateVolumeHidingEMM(
                                                securityParameter, EPSILON, ALPHA);
                                differentiallyPrivateVolumeHidingEMMs.put(securityParameter, emm);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testCorrectness(final int securityParameter) throws GeneralSecurityException {
        final var differentiallyPrivateVolumeHidingEMM =
                differentiallyPrivateVolumeHidingEMMs.get(securityParameter);
        final var multiMap = TestUtils.multimaps.get(securityParameter);
        final var searchLabel = TestUtils.searchLabels.get(securityParameter);
        final var encryptedIndex = differentiallyPrivateVolumeHidingEMM.buildIndex(multiMap);
        final var searchToken = differentiallyPrivateVolumeHidingEMM.trapdoor(searchLabel);
        final var ciphertextCounters =
                differentiallyPrivateVolumeHidingEMM.search(searchToken, encryptedIndex);
        final var searchToken2 =
                differentiallyPrivateVolumeHidingEMM.trapdoor(searchLabel, ciphertextCounters);
        final var ciphertexts =
                differentiallyPrivateVolumeHidingEMM.search2(searchToken2, encryptedIndex);
        final var values =
                differentiallyPrivateVolumeHidingEMM.result(ciphertexts).stream().sorted().toList();
        final var expectedValues = multiMap.get(searchLabel).stream().sorted().toList();

        // PROPERTY: Result(Search(Trapdoor(label), BuildIndex(multiMap))) = multiMap[label]
        assertEquals(expectedValues, values);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testBuildIndex(final int securityParameter) throws GeneralSecurityException {
        final var differentiallyPrivateVolumeHidingEMM =
                differentiallyPrivateVolumeHidingEMMs.get(securityParameter);
        final var multiMap = TestUtils.multimaps.get(securityParameter);
        final var encryptedIndexTables1 =
                ((DifferentiallyPrivateEncryptedIndexTables)
                                differentiallyPrivateVolumeHidingEMM.buildIndex(multiMap))
                        .getEncryptedIndexTables();
        final var encryptedIndexTables2 =
                ((DifferentiallyPrivateEncryptedIndexTables)
                                differentiallyPrivateVolumeHidingEMM.buildIndex(multiMap))
                        .getEncryptedIndexTables();
        final var table11 = ((EncryptedIndexTables) encryptedIndexTables1).getTable(0);
        final var table12 = ((EncryptedIndexTables) encryptedIndexTables1).getTable(1);
        final var table21 = ((EncryptedIndexTables) encryptedIndexTables2).getTable(0);
        final var table22 = ((EncryptedIndexTables) encryptedIndexTables2).getTable(1);
        final var labels =
                VolumeHidingEMMUtils.getDecryptedLabels(
                        differentiallyPrivateVolumeHidingEMM, table11, table12);
        final var labels2 =
                VolumeHidingEMMUtils.getDecryptedLabels(
                        differentiallyPrivateVolumeHidingEMM, table21, table22);

        // PROPERTY 1:  Encrypted labels for fixed EMM scheme and multimap are deterministic.
        // REASON:      Construction uses Cuckoo Hashing with stash with SHA3 hashes that are
        //              deterministic.
        assertEquals(labels, labels2);

        final var values =
                VolumeHidingEMMUtils.getDecryptedValues(
                        differentiallyPrivateVolumeHidingEMM, table11, table12);
        final var values2 =
                VolumeHidingEMMUtils.getDecryptedValues(
                        differentiallyPrivateVolumeHidingEMM, table21, table22);

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
                        () ->
                                new DifferentiallyPrivateVolumeHidingEMM(
                                        securityParameter, EPSILON, ALPHA));
        assertEquals(
                "Attempt to create key with invalid key size [" + securityParameter + "]: AES",
                exception.getMessage());
    }
}
