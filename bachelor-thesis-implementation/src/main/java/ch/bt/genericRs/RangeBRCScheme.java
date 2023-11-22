package ch.bt.genericRs;

import ch.bt.emm.EMM;
import ch.bt.model.*;
import ch.bt.model.Label;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.rc.RangeCoverUtils;
import ch.bt.rc.RangeCoveringAlgorithm;

import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

/** Falzon et al. */
public class RangeBRCScheme implements GenericRSScheme {
    private final EMM emmScheme;
    private final Graph<Vertex, DefaultEdge> graph;
    private final RangeCoveringAlgorithm rangeCoveringAlgorithm;

    private final Vertex root;

    public RangeBRCScheme(
            final int securityParameter,
            final EMM emmScheme,
            final Graph<Vertex, DefaultEdge> graph,
            final RangeCoveringAlgorithm rangeCoveringAlgorithm,
            final Vertex root) throws GeneralSecurityException, IOException {
        this.emmScheme = emmScheme;
        this.graph = graph;
        this.rangeCoveringAlgorithm = rangeCoveringAlgorithm;
        this.root = root;
        final var key = this.setup(securityParameter);
    }

    @Override
    public List<SecretKey> setup(final int securityParameter) throws GeneralSecurityException, IOException {
        return emmScheme.setup(securityParameter);
    }

    @Override
    public EncryptedIndex buildIndex(final Map<Label, Set<Plaintext>> multiMap) throws GeneralSecurityException {
        return emmScheme.buildIndex(multiMap);
    }

    @Override
    public List<SearchToken> trapdoor(CustomRange q) {
        final var rangeCover =
                rangeCoveringAlgorithm.getRangeCover(
                        graph, q, RangeCoverUtils.getVertex(graph, root.id()));
        /*
        final var token =
                rangeCover.stream()
                        .map(el -> emmScheme.trapdoor(el.range()))
                        .collect(Collectors.toList());
        Collections.shuffle(token);
        return token;
         */
        return null;
    }

    @Override
    public Set<Ciphertext> search(List<SearchToken> searchToken, EncryptedIndex encryptedIndex) {
        return searchToken.stream()
                .map(t -> {
                    try {
                        return emmScheme.search(t, encryptedIndex);
                    } catch (GeneralSecurityException e) {
                        throw new RuntimeException(e);
                    }
                })
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Plaintext> result(Set<Ciphertext> values) {
        // return emmScheme.result(values, ?);
        return null;
    }
}