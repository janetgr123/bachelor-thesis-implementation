package ch.bt.emm;

import static org.junit.jupiter.api.Assertions.*;

import ch.bt.model.EncryptedIndexMap;
import ch.bt.model.Label;
import ch.bt.model.Value;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class BasicEMMTest {

    private static final int MAX_NUMBER_OF_LABELS = 100;
    private static final int MAX_SIZE_VALUE_SET = 10;
    private static final List<Integer> VALID_SECURITY_PARAMETERS = List.of(256);

    private final static List<Integer> INVALID_SECURITY_PARAMETERS_FOR_HASH = List.of(128, 1024, 2048);

    private final static List<Integer> INVALID_SECURITY_PARAMETERS_FOR_SE = List.of(512);
    private final static Map<Integer, BasicEMM> basicEMMMs = new HashMap<>();

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
                            new BasicEMM(
                                    new SecureRandom(),
                                    securityParameter,
                                    multimaps.get(securityParameter));
                    basicEMMMs.put(securityParameter, emm);
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
        final var basicEMM = basicEMMMs.get(securityParameter);
        final var multimap = multimaps.get(securityParameter);
        final var searchLabel = searchLabels.get(securityParameter);
        final var encryptedIndex = basicEMM.buildIndex();
        final var searchToken = basicEMM.trapdoor(searchLabel);
        final var ciphertexts = basicEMM.search(searchToken, encryptedIndex);
        final var values = basicEMM.result(ciphertexts, searchLabel).stream().sorted().toList();
        final var expectedValues = multimap.get(searchLabel).stream().sorted().toList();
        assertEquals(values, expectedValues);
    }

    @ParameterizedTest
    @MethodSource("getValidSecurityParameters")
    public void testBuildIndex(final int securityParameter) {
        final var basicEMM = basicEMMMs.get(securityParameter);
        final var multimap = multimaps.get(securityParameter);
        final var searchLabel = searchLabels.get(securityParameter);
        final var encryptedIndex = ((EncryptedIndexMap) basicEMM.buildIndex()).map();
        final var encryptedIndex2 = ((EncryptedIndexMap) basicEMM.buildIndex()).map();
        final var labels = encryptedIndex.keySet().stream().sorted().toList();
        final var labels2 = encryptedIndex2.keySet().stream().sorted().toList();
        assertEquals(labels, labels2);

        final var token = basicEMM.getHMac().hash(searchLabel.label());
        final var tokenAndCounter =
                org.bouncycastle.util.Arrays.concatenate(
                        token, BigInteger.valueOf(0).toByteArray());
        final var encryptedLabel = basicEMM.getHash().hash(tokenAndCounter);
        final var matchingLabels =
                encryptedIndex.keySet().stream()
                        .filter(el -> Arrays.equals(el.label(), encryptedLabel))
                        .toList();
        assertEquals(1, matchingLabels.size());
        final var values = encryptedIndex.values();
        Set<Value> plaintexts = new HashSet<>();
        for (var el : values) {
            plaintexts.add(new Value(basicEMM.getSeScheme().decrypt(el.value())));
        }
        final var expectedValues = multimap.get(searchLabel);
        boolean[] found = new boolean[expectedValues.size()];
        int i = 0;
        for (var el2 : expectedValues) {
            for (var el : plaintexts) {
                if (Arrays.equals(el.value(), el2.value())) {
                    found[i] = true;
                    break;
                }
            }
            ++i;
        }
        IntStream.range(0, found.length).mapToObj(j -> found[j]).forEach(Assertions::assertTrue);
    }

    @ParameterizedTest
    @MethodSource("getInvalidSecurityParametersForHash")
    public void testNotMatchingHash(final int securityParameter) {
        Throwable exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> new BasicEMM(new SecureRandom(), securityParameter, new HashMap<>()));
        assertEquals("security parameter doesn't match hash", exception.getMessage());
    }

    @ParameterizedTest
    @MethodSource("getInvalidSecurityParametersForSE")
    public void testKeyTooLongForSE(final int securityParameter) {
        Throwable exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> new BasicEMM(new SecureRandom(), securityParameter, new HashMap<>()));
        assertEquals("security parameter too large", exception.getMessage());
    }
}
