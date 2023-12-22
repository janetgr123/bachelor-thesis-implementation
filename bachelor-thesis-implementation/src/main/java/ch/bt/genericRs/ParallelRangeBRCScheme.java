package ch.bt.genericRs;

import ch.bt.crypto.CastingHelpers;
import ch.bt.emm.EMM;
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
import java.util.concurrent.ForkJoinPool;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

/** Falzon et al. */
public class ParallelRangeBRCScheme implements GenericRSScheme {

    private static final ForkJoinPool FORK_JOIN_POOL = new ForkJoinPool();
    private final EMM emmScheme;
    private final RangeCoveringAlgorithm rangeCoveringAlgorithm;

    private final Vertex root;

    private Set<Vertex> rangeCover;

    public ParallelRangeBRCScheme(
            final int securityParameter,
            final EMM emmScheme,
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
                multiMap.keySet().parallelStream()
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
                FORK_JOIN_POOL
                        .submit(
                                () ->
                                        rangeCover.parallelStream()
                                                .map(Vertex::range)
                                                .map(CastingHelpers::toLabel)
                                                .map(
                                                        el -> {
                                                            try {
                                                                return emmScheme.trapdoor(el);
                                                            } catch (GeneralSecurityException
                                                                    | IOException e) {
                                                                throw new RuntimeException(e);
                                                            }
                                                        })
                                                .collect(Collectors.toList()))
                        .join();
        Collections.shuffle(token);
        return token;
    }

    @Override
    public Set<Ciphertext> search(List<SearchToken> searchToken, EncryptedIndex encryptedIndex) {
        return FORK_JOIN_POOL
                .submit(
                        () ->
                                searchToken.parallelStream()
                                        .map(
                                                t -> {
                                                    try {
                                                        return emmScheme.search(t, encryptedIndex);
                                                    } catch (GeneralSecurityException
                                                            | IOException e) {
                                                        throw new RuntimeException(e);
                                                    }
                                                })
                                        .flatMap(Collection::stream)
                                        .collect(Collectors.toSet()))
                .join();
    }

    @Override
    public Set<Plaintext> result(Set<Ciphertext> ciphertexts, final CustomRange q)
            throws GeneralSecurityException {
        return FORK_JOIN_POOL
                .submit(
                        () ->
                                rangeCover.parallelStream()
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
                                        .collect(Collectors.toSet()))
                .join();
    }

    @Override
    public String getClassOfEMM() {
        return emmScheme.getClass().getName();
    }

    @Override
    public int getIndexDummies() {
        return emmScheme.getNumberOfDummyValues();
    }

    @Override
    public EMM getEMM() {
        return emmScheme;
    }
}
