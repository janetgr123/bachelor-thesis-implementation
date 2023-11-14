package ch.bt.emm;

import ch.bt.model.EncryptedIndexTables;
import ch.bt.model.Pair;
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

public class VolumeHidingEMMTest {

    private final static int MAX_NUMBER_OF_LABELS = 100;
    private final static int MAX_SIZE_VALUE_SET = 10;

    private final static int ALPHA = 2;
    private final static List<Integer> VALID_SECURITY_PARAMETERS = List.of(256);

    private final static List<Integer> INVALID_SECURITY_PARAMETERS_FOR_HASH = List.of(128, 1024, 2048);

    private final static List<Integer> INVALID_SECURITY_PARAMETERS_FOR_SE = List.of(512);
    private final static Map<Integer, VolumeHidingEMM> volumeHidingEMMs = new HashMap<>();

    private final static Map<Integer, PlaintextLabel> searchLabels = new HashMap<>();

    private final static Map<Integer, Map<PlaintextLabel, Set<PlaintextValue>>> multimaps = new HashMap<>();

    @BeforeAll
    public static void init() {
        VALID_SECURITY_PARAMETERS.forEach(securityParameter -> {
                    searchLabels.put(securityParameter, buildMultiMapAndGenerateRandomSearchLabel(securityParameter));
                    final var emm = new VolumeHidingEMM(new SecureRandom(), new SecureRandom(), securityParameter, ALPHA, multimaps.get(securityParameter));
                    volumeHidingEMMs.put(securityParameter, emm);
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
        final var searchLabel = searchLabels.get(securityParameter);
        final var encryptedIndex = volumeHidingEMM.buildIndex();
        final var searchToken = volumeHidingEMM.trapdoor(searchLabel);
        final var ciphertexts = volumeHidingEMM.search(searchToken, encryptedIndex);
        final var values = volumeHidingEMM.result(ciphertexts, searchLabel).stream().sorted().toList();
        final var expectedValues = volumeHidingEMM.getMultiMap().get(searchLabel).stream().sorted().toList();
        assertEquals(values, expectedValues);
    }

    @ParameterizedTest
    @MethodSource("getValidSecurityParameters")
    public void testBuildIndex(final int securityParameter) {
        final var volumeHidingEMM = volumeHidingEMMs.get(securityParameter);
        final var table11 = ((EncryptedIndexTables) volumeHidingEMM.buildIndex()).getTable(0);
        final var table12 = ((EncryptedIndexTables) volumeHidingEMM.buildIndex()).getTable(1);
        final var table21 = ((EncryptedIndexTables) volumeHidingEMM.buildIndex()).getTable(0);
        final var table22 = ((EncryptedIndexTables) volumeHidingEMM.buildIndex()).getTable(1);
        final var labelsTable11 = Arrays.stream(table11).map(Pair::getLabel).toList();
        final var labelsTable12 = Arrays.stream(table12).map(Pair::getLabel).toList();
        labelsTable11.addAll(labelsTable12);
        final var labels = labelsTable11.stream().distinct().sorted().toList();
        final var labelsTable21 = Arrays.stream(table21).map(Pair::getLabel).toList();
        final var labelsTable22 = Arrays.stream(table22).map(Pair::getLabel).toList();
        labelsTable21.addAll(labelsTable22);
        final var labels2 = labelsTable21.stream().distinct().sorted().toList();
        assertEquals(labels, labels2);
    }

    @ParameterizedTest
    @MethodSource("getInvalidSecurityParametersForHash")
    public void testNotMatchingHash(final int securityParameter) {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> new VolumeHidingEMM(new SecureRandom(), new SecureRandom(), securityParameter, ALPHA, new HashMap<>()));
        assertEquals("security parameter doesn't match hash", exception.getMessage());
    }

    @ParameterizedTest
    @MethodSource("getInvalidSecurityParametersForSE")
    public void testKeyTooLongForSE(final int securityParameter) {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> new VolumeHidingEMM(new SecureRandom(), new SecureRandom(), securityParameter, ALPHA, new HashMap<>()));
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
