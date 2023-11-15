package ch.bt.emm;

import static org.junit.jupiter.api.Assertions.*;

import ch.bt.model.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Stream;

public class DifferentiallyPrivateVolumeHidingEMMTest {

    private static final int MAX_NUMBER_OF_LABELS = 100;
    private static final int MAX_SIZE_VALUE_SET = 10;

    private static final int ALPHA = 2;

    private static final double EPSILON = 0.2;
    private static final List<Integer> VALID_SECURITY_PARAMETERS = List.of(256);
    private static final List<Integer> INVALID_SECURITY_PARAMETERS_FOR_SE = List.of(512);
    private static final Map<Integer, DifferentiallyPrivateVolumeHidingEMM>
            differentiallyPrivateVolumeHidingEMMs = new HashMap<>();

    private static final Map<Integer, Label> searchLabels = new HashMap<>();

    private static final Map<Integer, Map<Label, Set<Value>>> multimaps = new HashMap<>();

    @BeforeAll
    public static void init() {
        VALID_SECURITY_PARAMETERS.forEach(
                securityParameter -> {
                    searchLabels.put(
                            securityParameter,
                            buildMultiMapAndGenerateRandomSearchLabel(securityParameter));
                    final var emm =
                            new DifferentiallyPrivateVolumeHidingEMM(
                                    new SecureRandom(),
                                    new SecureRandom(),
                                    securityParameter,
                                    EPSILON,
                                    ALPHA,
                                    multimaps.get(securityParameter));
                    differentiallyPrivateVolumeHidingEMMs.put(securityParameter, emm);
                });
    }

    private static Stream<Integer> getValidSecurityParameters() {
        return VALID_SECURITY_PARAMETERS.stream();
    }

    private static Stream<Integer> getInvalidSecurityParametersForSE() {
        return INVALID_SECURITY_PARAMETERS_FOR_SE.stream();
    }

    private static Label buildMultiMapAndGenerateRandomSearchLabel(final int securityParameter) {
        final Map<Label, Set<Value>> multimap = new HashMap<>();
        Label searchLabel = null;
        Random random = new Random();
        int index = (int) (MAX_NUMBER_OF_LABELS * Math.random()) + 1;
        while (multimap.size() < MAX_NUMBER_OF_LABELS) {
            final var values = new HashSet<Value>();
            int size = (int) (MAX_SIZE_VALUE_SET * Math.random()) + 1;
            while (values.size() < size) {
                byte[] v = new byte[securityParameter];
                random.nextBytes(v);
                values.add(new Value(v));
            }
            byte[] l = new byte[securityParameter];
            random.nextBytes(l);
            final var label = new Label(l);
            multimap.put(label, values);
            if (multimap.size() == index) {
                searchLabel = label;
            }
        }
        multimaps.put(securityParameter, multimap);
        return searchLabel;
    }

    @ParameterizedTest
    @MethodSource("getValidSecurityParameters")
    public void testCorrectness(final int securityParameter) {
        final var differentiallyPrivateVolumeHidingEMM =
                differentiallyPrivateVolumeHidingEMMs.get(securityParameter);
        final var searchLabel = searchLabels.get(securityParameter);
        final var encryptedIndex = differentiallyPrivateVolumeHidingEMM.buildIndex();
        final var searchToken = differentiallyPrivateVolumeHidingEMM.trapdoor(searchLabel);
        final var ciphertextCounters =
                differentiallyPrivateVolumeHidingEMM.search(searchToken, encryptedIndex);
        final var searchToken2 =
                differentiallyPrivateVolumeHidingEMM.trapdoor(searchLabel, ciphertextCounters);
        final var ciphertexts =
                differentiallyPrivateVolumeHidingEMM.search2(searchToken2, encryptedIndex);
        final var values =
                differentiallyPrivateVolumeHidingEMM.result(ciphertexts, searchLabel).stream()
                        .sorted()
                        .toList();
        final var expectedValues =
                differentiallyPrivateVolumeHidingEMM.getMultiMap().get(searchLabel).stream()
                        .sorted()
                        .toList();
        assertEquals(expectedValues, values);
    }

    @ParameterizedTest
    @MethodSource("getValidSecurityParameters")
    public void testBuildIndex(final int securityParameter) {
        final var differentiallyPrivateVolumeHidingEMM =
                differentiallyPrivateVolumeHidingEMMs.get(securityParameter);
        final var encryptedIndexTables1 =
                ((DifferentiallyPrivateEncryptedIndexTables)
                                differentiallyPrivateVolumeHidingEMM.buildIndex())
                        .getEncryptedIndexTables();
        final var encryptedIndexTables2 =
                ((DifferentiallyPrivateEncryptedIndexTables)
                                differentiallyPrivateVolumeHidingEMM.buildIndex())
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
        assertEquals(labels, labels2);
        final var values =
                VolumeHidingEMMUtils.getDecryptedValues(
                        differentiallyPrivateVolumeHidingEMM, table11, table12);
        final var values2 =
                VolumeHidingEMMUtils.getDecryptedValues(
                        differentiallyPrivateVolumeHidingEMM, table21, table22);
        assertEquals(values, values2);
    }

    @ParameterizedTest
    @MethodSource("getInvalidSecurityParametersForSE")
    public void testKeyTooLongForSE(final int securityParameter) {
        Throwable exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                new VolumeHidingEMM(
                                        new SecureRandom(),
                                        new SecureRandom(),
                                        securityParameter,
                                        ALPHA,
                                        new HashMap<>()));
        assertEquals("security parameter too large", exception.getMessage());
    }
}
