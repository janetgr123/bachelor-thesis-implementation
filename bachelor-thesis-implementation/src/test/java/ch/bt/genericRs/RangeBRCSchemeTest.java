package ch.bt.genericRs;

import static org.junit.jupiter.api.Assertions.assertEquals;

import ch.bt.TestConfigurations;
import ch.bt.TestUtils;
import ch.bt.emm.BasicEMM;
import ch.bt.emm.DifferentiallyPrivateVolumeHidingEMM;
import ch.bt.emm.VolumeHidingEMM;
import ch.bt.emm.VolumeHidingEMMOptimised;
import ch.bt.model.Label;
import ch.bt.model.Plaintext;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.bt.rc.BestRangeCover;

import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.stream.Collectors;

@ExtendWith({TestConfigurations.class})
public class RangeBRCSchemeTest {

    private static final Map<Integer, BasicEMM> basicEMMs = new HashMap<>();
    private static final Map<Integer, VolumeHidingEMM> volumeHidingEMMs = new HashMap<>();

    private static final Map<Integer, VolumeHidingEMMOptimised> volumeHidingOptimisedEMMs =
            new HashMap<>();

    private static final Map<Integer, DifferentiallyPrivateVolumeHidingEMM> dpVolumeHidingEMMs =
            new HashMap<>();

    private static final double EPSILON = 0.2;

    private static Map<Label, Set<Plaintext>> multimap;

    private static Graph<Vertex, DefaultEdge> graph;
    private static Vertex root;

    private static final CustomRange range = new CustomRange(27, 30);

    @BeforeAll
    public static void init() {
        multimap = TestUtils.multimap;
        graph = TestUtils.graph;
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
                                final var dpVhEmm =
                                        new DifferentiallyPrivateVolumeHidingEMM(
                                                securityParameter, EPSILON, TestUtils.ALPHA);
                                dpVolumeHidingEMMs.put(securityParameter, dpVhEmm);
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
                new RangeBRCScheme(securityParameter, basicEMM, graph, new BestRangeCover(), root);
        testRangeSchemeWithEMM(rangeScheme);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testCorrectnessWithVHEMM(final int securityParameter)
            throws GeneralSecurityException, IOException {
        final var volumeHidingEMM = volumeHidingEMMs.get(securityParameter);
        final var rangeScheme =
                new RangeBRCScheme(
                        securityParameter, volumeHidingEMM, graph, new BestRangeCover(), root);
        testRangeSchemeWithEMM(rangeScheme);
    }

    // TODO: FIX
    @Disabled
    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testCorrectnessWithVHOEMM(final int securityParameter)
            throws GeneralSecurityException, IOException {
        final var volumeHidingOEMM = volumeHidingOptimisedEMMs.get(securityParameter);
        final var rangeScheme =
                new RangeBRCScheme(
                        securityParameter, volumeHidingOEMM, graph, new BestRangeCover(), root);
        testRangeSchemeWithEMM(rangeScheme);
    }

    // TODO: FIX!!
    @Disabled
    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testCorrectnessWithDPVHEMM(final int securityParameter)
            throws GeneralSecurityException, IOException {
        final var dpVolumeHidingOEMM = dpVolumeHidingEMMs.get(securityParameter);
        final var rangeScheme =
                new RangeBRCScheme(
                        securityParameter, dpVolumeHidingOEMM, graph, new BestRangeCover(), root);
        testRangeSchemeWithEMM(rangeScheme);
    }

    private void testRangeSchemeWithEMM(final GenericRSScheme rangeScheme)
            throws GeneralSecurityException {
        final var encryptedIndex = rangeScheme.buildIndex(multimap);
        final var searchToken = rangeScheme.trapdoor(range);
        final var ciphertexts = rangeScheme.search(searchToken, encryptedIndex);
        final var values = rangeScheme.result(ciphertexts).stream().sorted().toList();
        final var expectedLabels =
                multimap.keySet().stream()
                        .filter(el -> range.contains(new BigInteger(el.label()).intValue()))
                        .collect(Collectors.toSet());
        final var expectedValues =
                expectedLabels.stream()
                        .map(el -> multimap.get(el))
                        .flatMap(Collection::stream)
                        .distinct()
                        .sorted()
                        .toList();

        // PROPERTY:    Result(Search(Trapdoor(range), BuildIndex(multiMap))) =
        //              union(multiMap[label] : label in range)
        var tmp = values.stream().map(el -> new BigInteger(el.data()).intValue()).sorted().toList();
        var tmp2 = expectedValues.stream().map(el -> new BigInteger(el.data()).intValue()).sorted().toList();
        assertEquals(expectedValues, values);
    }
}
