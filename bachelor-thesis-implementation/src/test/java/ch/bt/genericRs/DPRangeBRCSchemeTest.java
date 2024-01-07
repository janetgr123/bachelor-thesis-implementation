package ch.bt.genericRs;

import static org.junit.jupiter.api.Assertions.assertEquals;

import ch.bt.TestConfigurationsWithDB;
import ch.bt.TestUtils;
import ch.bt.crypto.CastingHelpers;
import ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.bt.rc.BestRangeCover;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.stream.Collectors;

@Disabled // this test takes very long
@ExtendWith({TestConfigurationsWithDB.class})
public class DPRangeBRCSchemeTest {

    private static final double EPSILON = 0.2;

    private static final Map<Integer, DifferentiallyPrivateVolumeHidingEMM>
            differentiallyPrivateVolumeHidingEMMs = new HashMap<>();

    private static Map<Label, Set<Plaintext>> multimap;

    private static Vertex root;

    private static final CustomRange range = new CustomRange(27, 55);

    @BeforeAll
    public static void init() {
        multimap = TestUtils.multimap;
        root = TestUtils.root;
        TestUtils.getValidSecurityParametersForAES()
                .forEach(
                        securityParameter -> {
                            try {
                                final var emm =
                                        new DifferentiallyPrivateVolumeHidingEMM(
                                                securityParameter, EPSILON, TestUtils.ALPHA);
                                differentiallyPrivateVolumeHidingEMMs.put(securityParameter, emm);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testCorrectnessWithDifferentiallyPrivateVolumeHidingEMM(final int securityParameter)
            throws GeneralSecurityException, IOException {
        final var dpVHEMM = differentiallyPrivateVolumeHidingEMMs.get(securityParameter);
        final var rangeScheme =
                new DPRangeBRCScheme(securityParameter, dpVHEMM, new BestRangeCover(), root);
        testRangeSchemeWithEMM(rangeScheme);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testCorrectnessParallelWithDifferentiallyPrivateVolumeHidingEMM(
            final int securityParameter) throws GeneralSecurityException, IOException {
        final var dpVHEMM = differentiallyPrivateVolumeHidingEMMs.get(securityParameter);
        final var rangeScheme =
                new ParallelDPRangeBRCScheme(
                        securityParameter, dpVHEMM, new BestRangeCover(), root);
        testRangeSchemeWithEMM(rangeScheme);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testDeterminismParallelWithDifferentiallyPrivateVolumeHidingEMM(
            final int securityParameter) throws GeneralSecurityException, IOException {
        final var dpVHEMM = differentiallyPrivateVolumeHidingEMMs.get(securityParameter);
        final var rangeScheme =
                new DPRangeBRCScheme(securityParameter, dpVHEMM, new BestRangeCover(), root);
        final var rangeSchemePar =
                new ParallelDPRangeBRCScheme(
                        securityParameter, dpVHEMM, new BestRangeCover(), root);
        testRangeSchemeWithEMM(rangeScheme, rangeSchemePar);
    }

    private void testRangeSchemeWithEMM(final TwoRoundGenericRSScheme rangeScheme)
            throws GeneralSecurityException, IOException {
        final var encryptedIndex = rangeScheme.buildIndex(multimap);
        final var searchToken = rangeScheme.trapdoor(range);
        final var ciphertexts = rangeScheme.search(searchToken, encryptedIndex);
        final var searchToken2 = rangeScheme.trapdoor(range, ciphertexts);
        final var ciphertexts2 = rangeScheme.search2(searchToken2, encryptedIndex);
        final var values =
                rangeScheme.result(ciphertexts2, range).stream().distinct().sorted().toList();
        final var expectedLabels =
                multimap.keySet().stream()
                        .filter(el -> range.contains(CastingHelpers.fromByteArrayToInt(el.label())))
                        .collect(Collectors.toSet());
        final var expectedValues =
                expectedLabels.stream()
                        .map(multimap::get)
                        .flatMap(Collection::stream)
                        .distinct()
                        .sorted()
                        .toList();

        // PROPERTY:    Result(Search(Trapdoor(range), BuildIndex(multiMap))) =
        //              union(multiMap[label] : label in range)
        assertEquals(expectedValues, values);
    }

    private void testRangeSchemeWithEMM(
            final TwoRoundGenericRSScheme rangeScheme, final TwoRoundGenericRSScheme rangeSchemePar)
            throws GeneralSecurityException, IOException {
        final var encryptedIndex = rangeScheme.buildIndex(multimap);
        final var searchToken = rangeScheme.trapdoor(range);
        final var ciphertexts = rangeScheme.search(searchToken, encryptedIndex);
        final var searchToken2 = rangeScheme.trapdoor(range, ciphertexts);
        final var ciphertexts2 = rangeScheme.search2(searchToken2, encryptedIndex);
        final var values =
                rangeScheme.result(ciphertexts2, range).stream().distinct().sorted().toList();
        final var encryptedIndexPar = rangeSchemePar.buildIndex(multimap);
        final var searchTokenPar = rangeSchemePar.trapdoor(range);
        final var ciphertextsPar = rangeSchemePar.search(searchTokenPar, encryptedIndexPar);
        final var searchToken2Par = rangeSchemePar.trapdoor(range, ciphertextsPar);
        final var ciphertexts2Par = rangeSchemePar.search2(searchToken2Par, encryptedIndexPar);
        final var valuesPar =
                rangeSchemePar.result(ciphertexts2Par, range).stream().distinct().sorted().toList();

        // PROPERTY:    parallel scheme is deterministic
        assertEquals(values, valuesPar);
    }
}
