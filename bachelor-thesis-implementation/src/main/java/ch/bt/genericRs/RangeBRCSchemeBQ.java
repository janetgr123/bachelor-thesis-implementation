package ch.bt.genericRs;

import ch.bt.crypto.CastingHelpers;
import ch.bt.emm.EMM;
import ch.bt.emm.blocked.BlockedQueries;
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

/**
 * This class implements a one round RangeBRCScheme based on the work from <a
 * href="https://doi.org/10.14778/3574245.3574247">Falzon et al.</a> using the blocked queries
 * technique from <a * href="https://doi.org/10.1007/978-3-030-30215-3_12">Markatou et al.</a>
 *
 * @author Janet Greutmann
 */
public class RangeBRCSchemeBQ implements GenericRSScheme {
    /** the EMM scheme */
    private final EMM emmScheme;

    /** the range covering algorithm */
    private final RangeCoveringAlgorithm rangeCoveringAlgorithm;

    /** the root vertex of the graph */
    private final Vertex root;

    /** database reconstruction error */
    private final int k;

    public RangeBRCSchemeBQ(
            final int securityParameter,
            final EMM emmScheme,
            final RangeCoveringAlgorithm rangeCoveringAlgorithm,
            final Vertex root,
            final int k)
            throws GeneralSecurityException, IOException {
        this.emmScheme = emmScheme;
        this.rangeCoveringAlgorithm = rangeCoveringAlgorithm;
        this.root = root;
        this.setup(securityParameter);
        this.k = k;
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
                multiMap.keySet().stream()
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
     *     encrypted index that cover the range q.
     */
    @Override
    public List<SearchToken> trapdoor(CustomRange q) {
        final var rangeWithNoise = BlockedQueries.blockedQuery(q, k);
        final var rangeCoverWithNoise = rangeCoveringAlgorithm.getRangeCover(rangeWithNoise, root);
        final var token =
                rangeCoverWithNoise.stream()
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

    /**
     * @param searchToken a list of search token that has been generated with trapdoor
     * @param encryptedIndex the encrypted index
     * @return the set of ciphertexts in the counter tables that correspond to the range encrypted
     *     in the token.
     */
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

    /**
     * @param ciphertexts the set of ciphertexts that search2 found for a given token list
     * @param q the range query
     * @return the corresponding set of plaintexts. The underlying EMM scheme is accessed in
     *     parallel.
     */
    @Override
    public Set<Plaintext> result(Set<Ciphertext> ciphertexts, final CustomRange q)
            throws GeneralSecurityException {
        final var rangeCover = rangeCoveringAlgorithm.getRangeCover(q, root);
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

    /**
     * Getter for the number of dummy entries in the encrypted index of the EMM
     *
     * @return the number of dummy values in the encrypted index of the EMM
     */
    @Override
    public int getIndexDummies() {
        return emmScheme.getNumberOfDummyValues();
    }

    /**
     * Getter for the EMM class
     *
     * @return the class of the EMM as a string
     */
    @Override
    public EMM getEMM() {
        return emmScheme;
    }

    /**
     * Getter for the EMM instance
     *
     * @return the EMM scheme instance
     */
    @Override
    public String getClassOfEMM() {
        return emmScheme.getClass().getName();
    }
}
