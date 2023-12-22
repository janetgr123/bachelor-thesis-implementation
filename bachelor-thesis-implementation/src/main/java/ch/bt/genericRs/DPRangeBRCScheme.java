package ch.bt.genericRs;

import ch.bt.crypto.CastingHelpers;
import ch.bt.emm.TwoRoundEMM;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.multimap.Ciphertext;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.rc.RangeCoverUtils;
import ch.bt.rc.RangeCoveringAlgorithm;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

/** Falzon et al. */
public class DPRangeBRCScheme implements TwoRoundGenericRSScheme {
    private final TwoRoundEMM emmScheme;
    private final RangeCoveringAlgorithm rangeCoveringAlgorithm;
    private final Vertex root;

    private Set<Vertex> rangeCover;

    public DPRangeBRCScheme(
            final int securityParameter,
            final TwoRoundEMM emmScheme,
            final RangeCoveringAlgorithm rangeCoveringAlgorithm,
            final Vertex root)
            throws GeneralSecurityException, IOException {
        this.emmScheme = emmScheme;
        this.rangeCoveringAlgorithm = rangeCoveringAlgorithm;
        this.root = root;
        this.setup(securityParameter);
    }

    @Override
    public List<SecretKey> setup(final int securityParameter)
            throws GeneralSecurityException, IOException {
        return emmScheme.setup(securityParameter);
    }

    @Override
    public EncryptedIndex buildIndex(final Map<Label, Set<Plaintext>> multiMap)
            throws GeneralSecurityException, IOException {
        final Map<Label, Set<Plaintext>> multiMapAccordingToGraph = new HashMap<>();
        final var keys =
                multiMap.keySet().stream()
                        .map(Label::label)
                        .map(CastingHelpers::fromByteArrayToInt)
                        .sorted()
                        .toList();
        final var rootVertex = RangeCoverUtils.getRoot(multiMap);
        RangeBRCSchemeUtils.addVertex(rootVertex, multiMapAccordingToGraph, keys, multiMap);
        return emmScheme.buildIndex(multiMapAccordingToGraph);
    }

    @Override
    public List<SearchToken> trapdoor(CustomRange q) {
        this.rangeCover = rangeCoveringAlgorithm.getRangeCover(q, root);
        final var token =
                rangeCover.stream()
                        .map(Vertex::range)
                        .map(CastingHelpers::toLabel)
                        .map(
                                el -> {
                                    try {
                                        return emmScheme.trapdoor(el);
                                    } catch (GeneralSecurityException | IOException e) {
                                        throw new RuntimeException(e);
                                    }
                                })
                        .collect(Collectors.toList());
        Collections.shuffle(token);
        return token;
    }

    @Override
    public List<SearchToken> trapdoor(CustomRange q, Set<Ciphertext> ciphertexts)
            throws GeneralSecurityException, IOException {
        final var token =
                rangeCover.stream()
                        .map(Vertex::range)
                        .map(CastingHelpers::toLabel)
                        .map(
                                el -> {
                                    try {
                                        return emmScheme.trapdoor(el, ciphertexts);
                                    } catch (GeneralSecurityException | IOException e) {
                                        throw new RuntimeException(e);
                                    }
                                })
                        .collect(Collectors.toList());
        Collections.shuffle(token);
        return token;
    }

    @Override
    public Set<Ciphertext> search(List<SearchToken> searchToken, EncryptedIndex encryptedIndex) {
        return searchToken.stream()
                .map(
                        t -> {
                            try {
                                return emmScheme.search(t, encryptedIndex);
                            } catch (GeneralSecurityException | IOException e) {
                                throw new RuntimeException(e);
                            }
                        })
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Ciphertext> search2(List<SearchToken> searchToken, EncryptedIndex encryptedIndex) {
        return searchToken.stream()
                .map(
                        t -> {
                            try {
                                return emmScheme.search2(t, encryptedIndex);
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                        })
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Plaintext> result(Set<Ciphertext> ciphertexts, final CustomRange q)
            throws GeneralSecurityException {
        return rangeCover.stream()
                .map(Vertex::range)
                .map(CastingHelpers::toLabel)
                .map(
                        el -> {
                            try {
                                return emmScheme.result(ciphertexts, el);
                            } catch (GeneralSecurityException e) {
                                throw new RuntimeException(e);
                            }
                        })
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());
    }

    @Override
    public String getClassOfEMM() {
        return "ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM";
    }

    @Override
    public int getIndexDummies() {
        return emmScheme.getNumberOfDummyValues();
    }@Override
    public int getIndexDummiesCT() {
        return emmScheme.getNumberOfDummyCT();
    }

    @Override
    public TwoRoundEMM getEMM() {
        return emmScheme;
    }
}
