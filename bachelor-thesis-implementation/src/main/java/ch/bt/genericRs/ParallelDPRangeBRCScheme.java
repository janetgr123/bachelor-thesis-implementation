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
import java.util.concurrent.ForkJoinPool;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

/**
 * This class implements a two round RangeBRCScheme using the Differentially Private Volume Hiding
 * SSE scheme from <a href="https://doi.org/10.1145/3319535.3354213">Patel et al.</a> The
 * RangeBRCScheme is based on the work from <a
 * href="https://doi.org/10.14778/3574245.3574247">Falzon et al.</a> It is an improved and
 * parallelized version of {@link ch.bt.genericRs.DPRangeBRCScheme}
 *
 * @author Janet Greutmann
 */
public class ParallelDPRangeBRCScheme implements TwoRoundGenericRSScheme {
    /** the fork join pool used for the parallelization */
    private static final ForkJoinPool FORK_JOIN_POOL = new ForkJoinPool();

    /** the EMM scheme */
    private final TwoRoundEMM emmScheme;

    /** the range covering algorithm */
    private final RangeCoveringAlgorithm rangeCoveringAlgorithm;

    /** the root vertex of the graph */
    private final Vertex root;

    /** the set of vertices that covers the range */
    private Set<Vertex> rangeCover;

    private int responsePadding;

    public ParallelDPRangeBRCScheme(
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

    /**
     * @param securityParameter the length of the keys in bits
     * @return two secret keys, one for the PRF and one for the symmetric encryption scheme
     * @throws GeneralSecurityException
     */
    @Override
    public List<SecretKey> setup(final int securityParameter)
            throws GeneralSecurityException, IOException {
        return emmScheme.setup(securityParameter);
    }

    /**
     * @param multiMap the plaintext data stored in a multimap
     * @return the encrypted index of the vertices of the graph
     * @throws GeneralSecurityException
     */
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

    /**
     * @param q the range query
     * @return a list of search token in random order that enable access to the entries in the
     *     encrypted index that cover the range q. The underlying EMM scheme is queried in parallel.
     */
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

    /**
     * @param q the range query
     * @param ciphertexts the ciphertexts returned by search
     * @return a list of search token in random order that enable access to the entries in the
     *     encrypted index that cover the range q. The underlying EMM scheme is queried in parallel.
     * @throws GeneralSecurityException
     */
    @Override
    public List<SearchToken> trapdoor(CustomRange q, Set<Ciphertext> ciphertexts)
            throws GeneralSecurityException, IOException {
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
                                                                return emmScheme.trapdoor(
                                                                        el, ciphertexts);
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

    /**
     * @param searchToken a list of search token that has been generated with trapdoor
     * @param encryptedIndex the encrypted index
     * @return the set of ciphertexts in the counter tables that correspond to the range encrypted
     *     in the token. The underlying EMM scheme is queried in parallel.
     */
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

    /**
     * @param searchToken a list of search token that has been generated with trapdoor(range,
     *     ciphertexts)
     * @param encryptedIndex the encrypted index
     * @return the set of ciphertexts that correspond to the range encrypted in the token. The
     *     underlying EMM scheme is queried in parallel.
     */
    @Override
    public Set<Ciphertext> search2(List<SearchToken> searchToken, EncryptedIndex encryptedIndex) {
        return FORK_JOIN_POOL
                .submit(
                        () ->
                                searchToken.parallelStream()
                                        .map(
                                                t -> {
                                                    try {
                                                        return emmScheme.search2(t, encryptedIndex);
                                                    } catch (IOException e) {
                                                        throw new RuntimeException(e);
                                                    }
                                                })
                                        .flatMap(Collection::stream)
                                        .collect(Collectors.toSet()))
                .join();
    }

    /**
     * @param ciphertexts the set of ciphertexts that search2 found for a given token list
     * @param q the range query
     * @return the corresponding set of plaintexts. The underlying EMM scheme is accessed in
     *     parallel.
     */
    @Override
    public Set<Plaintext> result(Set<Ciphertext> ciphertexts, final CustomRange q)
            throws GeneralSecurityException {
        responsePadding = 0;
        return FORK_JOIN_POOL
                .submit(
                        () ->
                                rangeCover.parallelStream()
                                        .map(Vertex::range)
                                        .map(CastingHelpers::toLabel)
                                        .map(
                                                el -> {
                                                    try {
                                                        final var result =
                                                                emmScheme.result(ciphertexts, el);
                                                        responsePadding +=
                                                                emmScheme.getResponsePadding();
                                                        return result;
                                                    } catch (GeneralSecurityException e) {
                                                        throw new RuntimeException(e);
                                                    }
                                                })
                                        .flatMap(Collection::stream)
                                        .collect(Collectors.toSet()))
                .join();
    }

    /**
     * Getter for the EMM class
     *
     * @return the class of the EMM as a string
     */
    @Override
    public String getClassOfEMM() {
        return "ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM";
    }

    /**
     * Getter for the number of dummy entries in the encrypted index of the EMM
     *
     * @return the number of dummy values in the encrypted index of the EMM
     */
    @Override
    public int getIndexDummies() {
        return emmScheme.getNumberOfDummyValues() + emmScheme.getNumberOfDummyCT();
    }

    /**
     * Getter for the EMM instance
     *
     * @return the EMM scheme instance
     */
    @Override
    public TwoRoundEMM getEMM() {
        return emmScheme;
    }

    @Override
    public int getResponsePadding() {
        return responsePadding;
    }
}
