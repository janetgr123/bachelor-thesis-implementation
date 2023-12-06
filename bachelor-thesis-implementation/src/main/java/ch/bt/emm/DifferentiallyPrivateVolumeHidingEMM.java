package ch.bt.emm;

import ch.bt.crypto.CastingHelpers;
import ch.bt.crypto.DPRF;
import ch.bt.model.*;
import ch.bt.model.Label;
import ch.bt.model.encryptedindex.DifferentiallyPrivateEncryptedIndexTables;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexTables;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.searchtoken.SearchTokenBytes;
import ch.bt.model.searchtoken.SearchTokenIntBytes;

import org.apache.commons.math3.distribution.LaplaceDistribution;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

/** SSE scheme from Patel et al. (2019) */
public class DifferentiallyPrivateVolumeHidingEMM extends VolumeHidingEMM {

    private static final int correctionFactor = 5610;

    private final double epsilon;
    private Stack<PairLabelNumberValues> counterStash;

    public DifferentiallyPrivateVolumeHidingEMM(
            final int securityParameter, final double epsilon, final double alpha)
            throws GeneralSecurityException {
        super(securityParameter, alpha);
        this.epsilon = epsilon;
    }

    @Override
    public EncryptedIndex buildIndex(final Map<Label, Set<Plaintext>> multiMap)
            throws GeneralSecurityException, IOException {
        final var encryptedIndex = super.buildIndex(multiMap);
        final int tableSize = getTableSize();
        final var seScheme = getSeScheme();

        final PairLabelNumberValues[] counterTable1 = new PairLabelNumberValues[tableSize];
        final PairLabelNumberValues[] counterTable2 = new PairLabelNumberValues[tableSize];
        final Stack<PairLabelNumberValues> counterStash = new Stack<>();
        VolumeHidingEMMUtils.doCuckooHashingWithStashCT(
                getMaxNumberOfEvictions(),
                counterTable1,
                counterTable2,
                multiMap,
                counterStash,
                tableSize,
                getPrfKey());
        VolumeHidingEMMUtils.fillEmptyValues(counterTable1);
        VolumeHidingEMMUtils.fillEmptyValues(counterTable2);
        this.counterStash = counterStash;

        final PairLabelCiphertext[] encryptedCounterTable1 = new PairLabelCiphertext[tableSize];
        final PairLabelCiphertext[] encryptedCounterTable2 = new PairLabelCiphertext[tableSize];
        VolumeHidingEMMUtils.encryptCounterTables(
                counterTable1,
                counterTable2,
                encryptedCounterTable1,
                encryptedCounterTable2,
                seScheme);

        return new DifferentiallyPrivateEncryptedIndexTables(
                encryptedIndex, encryptedCounterTable1, encryptedCounterTable2);
    }

    @Override
    public SearchToken trapdoor(final Label searchLabel)
            throws GeneralSecurityException, IOException {
        return new SearchTokenBytes(
                DPRF.generateToken(
                        getPrfKey(),
                        new Label(
                                org.bouncycastle.util.Arrays.concatenate(
                                        CastingHelpers.fromStringToByteArray("CT"),
                                        searchLabel.label()))));
    }

    public SearchToken trapdoor(final Label label, final Set<Ciphertext> ciphertexts)
            throws GeneralSecurityException, IOException {
        final var encryptedLabel = getSeScheme().encryptLabel(label);
        final var matchingEntries =
                ciphertexts.stream()
                        .map(PairLabelCiphertext.class::cast)
                        .filter(el -> el.label().equals(encryptedLabel))
                        .count();
        final var matchingEntriesInStash =
                counterStash.stream().filter(el -> el.label().equals(label)).count();
        final var mu = 0;
        final var beta = 2 / epsilon;
        final var laplaceDistribution = new LaplaceDistribution(mu, beta);
        final var noise = laplaceDistribution.sample();
        final var numberOfValuesWithNoise =
                (int) (matchingEntries + matchingEntriesInStash + correctionFactor + noise);
        final var token = DPRF.generateToken(getPrfKey(), label);
        return new SearchTokenIntBytes(numberOfValuesWithNoise, token);
    }

    @Override
    public Set<Ciphertext> search(
            final SearchToken searchToken, final EncryptedIndex encryptedIndex) throws IOException {
        if (!(encryptedIndex instanceof DifferentiallyPrivateEncryptedIndexTables)
                || !(searchToken instanceof SearchTokenBytes)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        Set<Ciphertext> ciphertexts = new HashSet<>();
        final var encryptedCounterTable =
                ((DifferentiallyPrivateEncryptedIndexTables) encryptedIndex).getCounterTable(0);
        final var encryptedCounterTable2 =
                ((DifferentiallyPrivateEncryptedIndexTables) encryptedIndex).getCounterTable(1);
        final var token = ((SearchTokenBytes) searchToken).token();
        final int numberOfValues = 1; // TODO: SET CORRECTLY!
        final int tableSize = getTableSize();
        for (int i = 0; i < numberOfValues; i++) {
            final var expand1 =
                    CastingHelpers.fromByteArrayToHashModN(
                            DPRF.evaluateDPRF(token, i, 0), tableSize);
            final var expand2 =
                    CastingHelpers.fromByteArrayToHashModN(
                            DPRF.evaluateDPRF(token, i, 1), tableSize);
            ciphertexts.add(encryptedCounterTable[expand1]);
            ciphertexts.add(encryptedCounterTable2[expand2]);
        }
        return ciphertexts;
    }

    public Set<Ciphertext> search2(
            final SearchToken searchToken, final EncryptedIndex encryptedIndex) throws IOException {
        if (!(encryptedIndex instanceof DifferentiallyPrivateEncryptedIndexTables)
                || !(searchToken instanceof SearchTokenIntBytes token)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        Set<Ciphertext> ciphertexts = new HashSet<>();
        final var encryptedIndexTables =
                ((DifferentiallyPrivateEncryptedIndexTables) encryptedIndex)
                        .getEncryptedIndexTables();
        if (!(encryptedIndexTables instanceof EncryptedIndexTables tables)) {
            throw new IllegalArgumentException("types of encrypted index tables are not matching");
        }
        final var encryptedIndexTable1 = tables.getTable(0);
        final var encryptedIndexTable2 = tables.getTable(1);
        final var numberOfValues = token.token();
        final int tableSize = getTableSize();
        int i = 0;
        while (i < numberOfValues) {
            final var expand1 =
                    CastingHelpers.fromByteArrayToHashModN(
                            DPRF.evaluateDPRF(token.token2(), i, 0), tableSize);
            final var expand2 =
                    CastingHelpers.fromByteArrayToHashModN(
                            DPRF.evaluateDPRF(token.token2(), i, 1), tableSize);
            ciphertexts.add(encryptedIndexTable1[expand1]);
            ciphertexts.add(encryptedIndexTable2[expand2]);
            i++;
        }
        return ciphertexts;
    }
}
