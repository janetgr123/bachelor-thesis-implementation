package ch.bt.emm;

import ch.bt.model.PlaintextLabel;
import ch.bt.model.PlaintextValue;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

// TODO: FIX
@Disabled
public class VolumeHidingEMMTest {

    private final static int MAX_NUMBER_OF_LABELS = 100;
    private final static int MAX_SIZE_VALUE_SET = 10;
    private final static List<Integer> VALID_SECURITY_PARAMETERS = List.of(256);

    private final static List<Integer> INVALID_SECURITY_PARAMETERS_FOR_HASH = List.of(128, 1024, 2048);

    private final static List<Integer> INVALID_SECURITY_PARAMETERS_FOR_SE = List.of(512);
    private final static Map<Integer, VolumeHidingEMM> volumeHidingEMMs = new HashMap<>();

    private final static Map<Integer, PlaintextLabel> searchLabels = new HashMap<>();

    private final static Map<Integer, Map<PlaintextLabel, Set<PlaintextValue>>> multimaps = new HashMap<>();

    @BeforeAll
    public static void init() {
        VALID_SECURITY_PARAMETERS.forEach(securityParameter -> {
                    final var emm = new VolumeHidingEMM(new SecureRandom(), securityParameter);
                    volumeHidingEMMs.put(securityParameter, emm);
                    searchLabels.put(securityParameter, buildMultiMapAndGenerateRandomSearchLabel(securityParameter));
                }
        );
    }

    private static Stream<Integer> getValidSecurityParameters() {
        return VALID_SECURITY_PARAMETERS.stream();
    }

    private static Stream<Integer> getInvalidSecurityParametersForHash() {
        return INVALID_SECURITY_PARAMETERS_FOR_HASH.stream();
    }

    private static Stream<Integer> getInvalidSecurityParametersForSE() {
        return INVALID_SECURITY_PARAMETERS_FOR_SE.stream();
    }

    @ParameterizedTest
    @MethodSource("getValidSecurityParameters")
    public void testCorrectness(final int securityParameter) {
        final var volumeHidingEMM = volumeHidingEMMs.get(securityParameter);
        final var multimap = multimaps.get(securityParameter);
        final var searchLabel = searchLabels.get(securityParameter);
        final var encryptedIndex = volumeHidingEMM.buildIndex(multimap);
        final var searchToken = volumeHidingEMM.trapdoor(searchLabel);
        final var ciphertexts = volumeHidingEMM.search(searchToken, encryptedIndex);
        final var values = volumeHidingEMM.result(ciphertexts).stream().sorted().toList();
        final var expectedValues = multimap.get(searchLabel).stream().sorted().toList();
        assertEquals(values, expectedValues);
    }

    @ParameterizedTest
    @MethodSource("getValidSecurityParameters")
    public void testBuildIndex(final int securityParameter) {
        final var volumeHidingEMM = volumeHidingEMMs.get(securityParameter);
        final var multimap = multimaps.get(securityParameter);
        final var searchLabel = searchLabels.get(securityParameter);
        final var encryptedIndex = volumeHidingEMM.buildIndex(multimap);
        final var encryptedIndex2 = volumeHidingEMM.buildIndex(multimap);
        final var labels = encryptedIndex.keySet().stream().sorted().toList();
        final var labels2 = encryptedIndex2.keySet().stream().sorted().toList();
        assertEquals(labels, labels2);

        // TODO: test values
    }

    @ParameterizedTest
    @MethodSource("getInvalidSecurityParametersForHash")
    public void testNotMatchingHash(final int securityParameter) {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> new VolumeHidingEMM(new SecureRandom(), securityParameter));
        assertEquals("security parameter doesn't match hash", exception.getMessage());
    }

    @ParameterizedTest
    @MethodSource("getInvalidSecurityParametersForSE")
    public void testKeyTooLongForSE(final int securityParameter) {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> new VolumeHidingEMM(new SecureRandom(), securityParameter));
        assertEquals("security parameter too large", exception.getMessage());
    }

    private static PlaintextLabel buildMultiMapAndGenerateRandomSearchLabel(final int securityParameter) {
        final Map<PlaintextLabel, Set<PlaintextValue>> multimap = new HashMap<>();
        PlaintextLabel searchLabel = null;
        Random random = new Random();
        int index = (int) (MAX_NUMBER_OF_LABELS * Math.random());
        while (multimap.size() < MAX_NUMBER_OF_LABELS) {
            final var values = new HashSet<PlaintextValue>();
            int size = (int) (MAX_SIZE_VALUE_SET * Math.random()) + 1;
            while (values.size() < size) {
                byte[] v = new byte[securityParameter];
                random.nextBytes(v);
                values.add(new PlaintextValue(v));
            }
            byte[] l = new byte[securityParameter];
            random.nextBytes(l);
            final var label = new PlaintextLabel(l);
            multimap.put(label, values);
            if (multimap.size() == index) {
                searchLabel = label;
            }
        }
        multimaps.put(securityParameter, multimap);
        return searchLabel;
    }
}
