package ch.bt.emm;

import static org.junit.jupiter.api.Assertions.*;

import ch.bt.model.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Stream;

public class VolumeHidingEMMTest {

    private static final int MAX_NUMBER_OF_LABELS = 2;
    private static final int MAX_SIZE_VALUE_SET = 3;

    private static final int ALPHA = 2;
    private static final List<Integer> VALID_SECURITY_PARAMETERS = List.of(256);

    private static final List<Integer> INVALID_SECURITY_PARAMETERS_FOR_HASH =
            List.of(128, 1024, 2048);

    private static final List<Integer> INVALID_SECURITY_PARAMETERS_FOR_SE = List.of(512);
    private static final Map<Integer, VolumeHidingEMM> volumeHidingEMMs = new HashMap<>();

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
                            new VolumeHidingEMM(
                                    new SecureRandom(),
                                    new SecureRandom(),
                                    securityParameter,
                                    ALPHA,
                                    multimaps.get(securityParameter));
                    volumeHidingEMMs.put(securityParameter, emm);
                });
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
        final var volumeHidingEMM = volumeHidingEMMs.get(securityParameter);
        final var searchLabel = searchLabels.get(securityParameter);
        final var encryptedIndex = volumeHidingEMM.buildIndex();
        final var searchToken = volumeHidingEMM.trapdoor(searchLabel);
        final var ciphertexts = volumeHidingEMM.search(searchToken, encryptedIndex);
        final var values =
                volumeHidingEMM.result(ciphertexts, searchLabel).stream().sorted().toList();
        final var expectedValues =
                volumeHidingEMM.getMultiMap().get(searchLabel).stream().sorted().toList();
        assertEquals(expectedValues, values);
    }

    @ParameterizedTest
    @MethodSource("getValidSecurityParameters")
    public void testBuildIndex(final int securityParameter) {
        final var volumeHidingEMM = volumeHidingEMMs.get(securityParameter);
        final var table11 = ((EncryptedIndexTables) volumeHidingEMM.buildIndex()).getTable(0);
        final var table12 = ((EncryptedIndexTables) volumeHidingEMM.buildIndex()).getTable(1);
        final var table21 = ((EncryptedIndexTables) volumeHidingEMM.buildIndex()).getTable(0);
        final var table22 = ((EncryptedIndexTables) volumeHidingEMM.buildIndex()).getTable(1);
        final var labels = getDecryptedLabels(volumeHidingEMM, table11, table12);
        final var labels2 = getDecryptedLabels(volumeHidingEMM, table21, table22);
        assertEquals(labels, labels2);
        final var values = getDecryptedLabels(volumeHidingEMM, table11, table12);
        final var values2 = getDecryptedLabels(volumeHidingEMM, table21, table22);
        assertEquals(values, values2);
    }

    private List<Label> getDecryptedLabels(
            final VolumeHidingEMM volumeHidingEMM, final PairLabelValue[] table1, final PairLabelValue[] table2) {
        final var labelsTable1 = Arrays.stream(table1).map(PairLabelValue::getLabel).toList();
        final var labelsTable2 = Arrays.stream(table2).map(PairLabelValue::getLabel).toList();
        final var labelsTables = new ArrayList<>(labelsTable1);
        labelsTables.addAll(labelsTable2);
        return labelsTables.stream()
                .map(el -> volumeHidingEMM.getSeScheme().decrypt(el.getLabel()))
                .map(Label::new)
                .distinct()
                .sorted()
                .toList();
    }

    private List<Value> getDecryptedValues(
            final VolumeHidingEMM volumeHidingEMM, final PairLabelValue[] table1, final PairLabelValue[] table2) {
        final var valuesTable1 = Arrays.stream(table1).map(PairLabelValue::getValue).toList();
        final var valuesTable2 = Arrays.stream(table2).map(PairLabelValue::getValue).toList();
        final var valuesTables = new ArrayList<>(valuesTable1);
        valuesTables.addAll(valuesTable2);
        return valuesTables.stream()
                .map(el -> volumeHidingEMM.getSeScheme().decrypt(el.getValue()))
                .map(Value::new)
                .distinct()
                .sorted()
                .toList();
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
