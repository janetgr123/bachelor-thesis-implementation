package ch.bt.emm;

import static org.junit.jupiter.api.Assertions.*;

import ch.bt.TestConfigurationsWithDB;
import ch.bt.TestUtils;
import ch.bt.emm.dpVolumeHiding.NonInteractiveDifferentiallyPrivateVolumeHidingEMM;
import ch.bt.emm.dpVolumeHiding.NonInteractiveDifferentiallyPrivateVolumeHidingEMM2;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

@ExtendWith({TestConfigurationsWithDB.class})
public class NonInteractiveDifferentiallyPrivateVolumeHidingEMMTest {
    private static final double EPSILON = 0.2;
    private static final Map<Integer, NonInteractiveDifferentiallyPrivateVolumeHidingEMM>
            differentiallyPrivateVolumeHidingEMMs = new HashMap<>();
    private static final Map<Integer, NonInteractiveDifferentiallyPrivateVolumeHidingEMM2>
            differentiallyPrivateVolumeHidingEMM2s = new HashMap<>();

    private static Map<Label, Set<Plaintext>> multiMap;

    private static Label searchLabel;

    @BeforeAll
    public static void init() {
        multiMap = TestUtils.multimap;
        searchLabel = TestUtils.searchLabel;
        TestUtils.getValidSecurityParametersForAES()
                .forEach(
                        securityParameter -> {
                            try {
                                final var emm =
                                        new NonInteractiveDifferentiallyPrivateVolumeHidingEMM(
                                                securityParameter,
                                                EPSILON,
                                                TestUtils.ALPHA,
                                                TestUtils.T);
                                differentiallyPrivateVolumeHidingEMMs.put(securityParameter, emm);
                                final var emm2 =
                                        new NonInteractiveDifferentiallyPrivateVolumeHidingEMM2(
                                                securityParameter,
                                                EPSILON,
                                                TestUtils.ALPHA,
                                                TestUtils.T);
                                differentiallyPrivateVolumeHidingEMM2s.put(securityParameter, emm2);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testCorrectness(final int securityParameter)
            throws GeneralSecurityException, IOException {
        final var differentiallyPrivateVolumeHidingEMM =
                differentiallyPrivateVolumeHidingEMMs.get(securityParameter);
        testCorrectness(differentiallyPrivateVolumeHidingEMM);
    }

    @ParameterizedTest
    @MethodSource("ch.bt.TestUtils#getValidSecurityParametersForAES")
    public void testCorrectness2(final int securityParameter)
            throws GeneralSecurityException, IOException {
        final var differentiallyPrivateVolumeHidingEMM =
                differentiallyPrivateVolumeHidingEMM2s.get(securityParameter);
        testCorrectness(differentiallyPrivateVolumeHidingEMM);
    }

    public void testCorrectness(final EMM emm) throws GeneralSecurityException, IOException {
        final var encryptedIndex = emm.buildIndex(multiMap);
        final var searchToken = emm.trapdoor(searchLabel);
        final var ciphertexts = emm.search(searchToken, encryptedIndex);
        final var values = emm.result(ciphertexts, searchLabel).stream().sorted().toList();
        final var expectedValues = multiMap.get(searchLabel).stream().sorted().toList();

        // PROPERTY: Result(Search(Trapdoor(label), BuildIndex(multiMap))) = multiMap[label]
        assertEquals(expectedValues, values);
    }
}
