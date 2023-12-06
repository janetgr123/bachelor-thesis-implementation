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
import ch.bt.rc.RangeCoveringAlgorithm;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

/** Falzon et al. */
public class RangeBRCScheme implements GenericRSScheme {
    private final EMM emmScheme;
    private final RangeCoveringAlgorithm rangeCoveringAlgorithm;

    private final Vertex root;

    public RangeBRCScheme(
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
                multiMap.keySet().stream()
                        .map(Label::label)
                        .map(CastingHelpers::fromByteArrayToInt)
                        .sorted()
                        .toList();
        final var size = keys.size();
        final var min = keys.get(0);
        final var max = keys.get(size - 1);
        final var root = new CustomRange(min, max);
        final var rootVertex =
                new Vertex(String.join("-", String.valueOf(min), String.valueOf(max)), root);
        RangeBRCSchemeUtils.addVertex(rootVertex, multiMapAccordingToGraph, keys, multiMap);
        return emmScheme.buildIndex(multiMapAccordingToGraph);
    }

    @Override
    public List<SearchToken> trapdoor(CustomRange q) {
        final var rangeCover = rangeCoveringAlgorithm.getRangeCover(q, root);
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
    public Set<Plaintext> result(Set<Ciphertext> ciphertexts, final CustomRange q)
            throws GeneralSecurityException {
        return emmScheme.result(ciphertexts, CastingHelpers.toLabel(q));
    }
}
