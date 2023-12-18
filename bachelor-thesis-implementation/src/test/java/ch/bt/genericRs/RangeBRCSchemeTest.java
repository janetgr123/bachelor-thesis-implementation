package ch.bt.genericRs;

import static org.junit.jupiter.api.Assertions.assertEquals;

import ch.bt.TestConfigurationsWithDB;
import ch.bt.TestUtils;
import ch.bt.crypto.CastingHelpers;
import ch.bt.emm.basic.BasicEMM;
import ch.bt.emm.volumeHiding.VolumeHidingEMM;
import ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.bt.rc.BestRangeCover;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.stream.Collectors;

@ExtendWith({TestConfigurationsWithDB.class})
public class RangeBRCSchemeTest {

    private static final Map<Integer, BasicEMM> basicEMMs = new HashMap<>();
    private static final Map<Integer, VolumeHidingEMM> volumeHidingEMMs = new HashMap<>();

    private static final Map<Integer, VolumeHidingEMMOptimised> volumeHidingOptimisedEMMs =
            new HashMap<>();

    private static Map<Label, Set<Plaintext>> multimap;

    private static Vertex root;

    private static final CustomRange range = new CustomRange(2,11);

    @BeforeAll
    public static void init() {
        multimap = TestUtils.multimap;
        root = TestUtils.root;
        TestUtils.getValidSecurityParametersForAES()
                .forEach(
                        securityParameter -> {
                            try {
                                final var emm = new BasicEMM(securityParameter);
                                basicEMMs.put(securityParameter, emm);
                                final var vhEmm =
                                        new VolumeHidingEMM(securityParameter, TestUtils.ALPHA);
                                volumeHidingEMMs.put(securityParameter, vhEmm);
                                final var vhOEmm =
                                        new VolumeHidingEMMOptimised(
                                                securityParameter, TestUtils.ALPHA);
                                volumeHidingOptimisedEMMs.put(securityParameter, vhOEmm);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testCorrectnessWithBasicEMM(final int securityParameter)
            throws GeneralSecurityException, IOException {
        final var basicEMM = basicEMMs.get(securityParameter);
        final var rangeScheme =
                new RangeBRCScheme(securityParameter, basicEMM, new BestRangeCover(), root);
        testRangeSchemeWithEMM(rangeScheme);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testCorrectnessParallelWithBasicEMM(final int securityParameter)
            throws GeneralSecurityException, IOException {
        final var basicEMM = basicEMMs.get(securityParameter);
        final var rangeScheme =
                new ParallelRangeBRCScheme(securityParameter, basicEMM, new BestRangeCover(), root);
        testRangeSchemeWithEMM(rangeScheme);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testDeterminismParallelWithBasicEMM(final int securityParameter)
            throws GeneralSecurityException, IOException {
        final var basicEMM = basicEMMs.get(securityParameter);
        final var rangeScheme =
                new RangeBRCScheme(securityParameter, basicEMM, new BestRangeCover(), root);
        final var rangeSchemePar =
                new ParallelRangeBRCScheme(securityParameter, basicEMM, new BestRangeCover(), root);
        testRangeSchemeWithEMM(rangeScheme, rangeSchemePar);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testCorrectnessWithVHEMM(final int securityParameter)
            throws GeneralSecurityException, IOException {
        final var volumeHidingEMM = volumeHidingEMMs.get(securityParameter);
        final var rangeScheme =
                new RangeBRCScheme(securityParameter, volumeHidingEMM, new BestRangeCover(), root);
        testRangeSchemeWithEMM(rangeScheme);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testCorrectnessWithVHOEMM(final int securityParameter)
            throws GeneralSecurityException, IOException {
        final var volumeHidingOEMM = volumeHidingOptimisedEMMs.get(securityParameter);
        final var rangeScheme =
                new RangeBRCScheme(securityParameter, volumeHidingOEMM, new BestRangeCover(), root);
        testRangeSchemeWithEMM(rangeScheme);
    }

    private void testRangeSchemeWithEMM(final GenericRSScheme rangeScheme)
            throws GeneralSecurityException, IOException {
        final var encryptedIndex = rangeScheme.buildIndex(multimap);
        final var searchToken = rangeScheme.trapdoor(range);
        final var ciphertexts = rangeScheme.search(searchToken, encryptedIndex);
        final var values =
                rangeScheme.result(ciphertexts, range).stream().distinct().sorted().toList();
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
            final GenericRSScheme rangeScheme, final GenericRSScheme parallelRangeScheme)
            throws GeneralSecurityException, IOException {
        final var encryptedIndex = rangeScheme.buildIndex(multimap);
        final var searchToken = rangeScheme.trapdoor(range);
        final var ciphertexts = rangeScheme.search(searchToken, encryptedIndex);
        final var values =
                rangeScheme.result(ciphertexts, range).stream().distinct().sorted().toList();
        final var encryptedIndexPar = parallelRangeScheme.buildIndex(multimap);
        final var searchTokenPar = parallelRangeScheme.trapdoor(range);
        final var ciphertextsPar = parallelRangeScheme.search(searchTokenPar, encryptedIndexPar);
        final var valuesPar =
                parallelRangeScheme.result(ciphertextsPar, range).stream()
                        .distinct()
                        .sorted()
                        .toList();

        // PROPERTY:  parallel version of scheme is deterministic
        assertEquals(values, valuesPar);
    }
}
