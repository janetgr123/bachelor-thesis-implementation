package ch.bt.emm.dpVolumeHiding;

import ch.bt.crypto.*;
import ch.bt.emm.TwoRoundEMM;
import ch.bt.emm.volumeHiding.VolumeHidingEMMUtils;
import ch.bt.model.encryptedindex.DifferentiallyPrivateEncryptedIndexTables;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexTables;
import ch.bt.model.multimap.*;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.searchtoken.SearchTokenBytes;
import ch.bt.model.searchtoken.SearchTokenIntBytes;

import org.apache.commons.math3.distribution.LaplaceDistribution;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

import javax.crypto.SecretKey;

/** SSE scheme from Patel et al. (2019) */
public class DifferentiallyPrivateVolumeHidingEMM implements TwoRoundEMM {

    private static final int correctionFactor = 5610;

    private final double epsilon;
    private Stack<Ciphertext> counterStash;
    private final SEScheme seScheme;
    private int tableSize;

    private Stack<Ciphertext> stash;
    private final double alpha;

    private final SecretKey prfKey;

    private int maxNumberOfValuesPerLabel = 0;

    private int numberOfDummyValues;

    private int numberOfDummyCT;

    public DifferentiallyPrivateVolumeHidingEMM(
            final int securityParameter, final double epsilon, final double alpha)
            throws GeneralSecurityException {
        final var keys = this.setup(securityParameter);
        this.prfKey = keys.get(0);
        this.seScheme = new AESSEScheme(keys.get(1));
        this.alpha = alpha;
        this.epsilon = epsilon;
    }

    private void setMaxNumberOfValuesPerLabel(final Map<Label, Set<Plaintext>> multiMap) {
        final var keys = multiMap.keySet();
        for (final var key : keys) {
            final var num = multiMap.get(key).size();
            if (num > maxNumberOfValuesPerLabel) {
                maxNumberOfValuesPerLabel = num;
            }
        }
    }

    @Override
    public List<SecretKey> setup(int securityParameter) throws GeneralSecurityException {
        final var key1 = CryptoUtils.generateKeyWithHMac(securityParameter);
        final var key2 = CryptoUtils.generateKeyForAES(securityParameter);
        return List.of(key1, key2);
    }

    @Override
    public EncryptedIndex buildIndex(final Map<Label, Set<Plaintext>> multiMap)
            throws GeneralSecurityException, IOException {
        final int numberOfValues = VolumeHidingEMMUtils.getNumberOfValues(multiMap);
        this.tableSize = (int) Math.round((1 + alpha) * numberOfValues);

        setMaxNumberOfValuesPerLabel(multiMap);
        final var encryptedIndexWithStash =
                VolumeHidingEMMUtils.calculateEncryptedIndexAndStash(
                        tableSize, numberOfValues, multiMap, prfKey, seScheme);

        final var encryptedIndex = encryptedIndexWithStash.encryptedIndex();
        this.stash = encryptedIndexWithStash.stash();
        this.numberOfDummyValues = encryptedIndexWithStash.numberOfDummyValues();

        final var encryptedCTIndexWithStash =
                DPVolumeHidingEMMUtils.calculateEncryptedCTIndex(
                        tableSize, numberOfValues, multiMap, prfKey, seScheme);
        final var encryptedCTIndex = encryptedCTIndexWithStash.encryptedIndex();
        this.counterStash = encryptedCTIndexWithStash.stash();
        this.numberOfDummyCT = encryptedCTIndexWithStash.numberOfDummyValues();

        return new DifferentiallyPrivateEncryptedIndexTables(encryptedIndex, encryptedCTIndex);
    }

    @Override
    public SearchToken trapdoor(final Label searchLabel)
            throws GeneralSecurityException, IOException {
        return new SearchTokenBytes(
                DPRF.generateToken(
                        prfKey,
                        new Label(
                                org.bouncycastle.util.Arrays.concatenate(
                                        CastingHelpers.fromStringToByteArray("CT"),
                                        searchLabel.label()))));
    }

    @Override
    public SearchToken trapdoor(final Label label, final Set<Ciphertext> ciphertexts)
            throws GeneralSecurityException, IOException {
        final var encryptedLabel = seScheme.encryptLabel(label);
        final var matchingEntries =
                ciphertexts.stream()
                        .map(PairLabelCiphertext.class::cast)
                        .filter(el -> el.label().equals(encryptedLabel))
                        .count();
        final var matchingEntriesInStash =
                counterStash.stream()
                        .map(PairLabelPlaintext.class::cast)
                        .filter(el -> el.label().equals(label))
                        .count();
        final var mu = 0;
        final var beta = 2 / epsilon;
        final var laplaceDistribution = new LaplaceDistribution(mu, beta);
        final var noise = laplaceDistribution.sample();
        final var numberOfValuesWithNoise =
                (int) (matchingEntries + matchingEntriesInStash + correctionFactor + noise);
        final var token = DPRF.generateToken(prfKey, label);
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
        final var encryptedCouterIndex =
                (EncryptedIndexTables)
                        ((DifferentiallyPrivateEncryptedIndexTables) encryptedIndex)
                                .encryptedIndexCT();
        final var encryptedCounterTable = encryptedCouterIndex.getTable(0);
        final var encryptedCounterTable2 = encryptedCouterIndex.getTable(1);
        final var token = ((SearchTokenBytes) searchToken).token();
        for (int i = 0; i < maxNumberOfValuesPerLabel; i++) {
            final var expand1 =
                    CastingHelpers.fromByteArrayToHashModN(
                            DPRF.evaluateDPRF(token, i, 0), tableSize);
            final var expand2 =
                    CastingHelpers.fromByteArrayToHashModN(
                            DPRF.evaluateDPRF(token, i, 1), tableSize);
            final var ciphertext1 = encryptedCounterTable[expand1];
            final var ciphertext2 = encryptedCounterTable2[expand2];
            ciphertexts.add(ciphertext1);
            ciphertexts.add(ciphertext2);
        }
        return ciphertexts;
    }

    @Override
    public Set<Plaintext> result(Set<Ciphertext> ciphertexts, Label searchLabel)
            throws GeneralSecurityException {
        return VolumeHidingEMMUtils.getPlaintexts(ciphertexts, seScheme, searchLabel, stash);
    }

    @Override
    public Set<Ciphertext> search2(
            final SearchToken searchToken, final EncryptedIndex encryptedIndex) throws IOException {
        if (!(encryptedIndex instanceof DifferentiallyPrivateEncryptedIndexTables)
                || !(searchToken instanceof SearchTokenIntBytes token)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        Set<Ciphertext> ciphertexts = new HashSet<>();
        final var encryptedIndexTables =
                (EncryptedIndexTables)
                        ((DifferentiallyPrivateEncryptedIndexTables) encryptedIndex)
                                .encryptedIndex();
        final var encryptedIndexTable1 = encryptedIndexTables.getTable(0);
        final var encryptedIndexTable2 = encryptedIndexTables.getTable(1);
        final var numberOfValues = token.token();
        int i = 0;
        while (i < numberOfValues) {
            final var expand1 =
                    CastingHelpers.fromByteArrayToHashModN(
                            DPRF.evaluateDPRF(token.token2(), i, 0), tableSize);
            final var expand2 =
                    CastingHelpers.fromByteArrayToHashModN(
                            DPRF.evaluateDPRF(token.token2(), i, 1), tableSize);
            final var ciphertext1 = encryptedIndexTable1[expand1];
            final var ciphertext2 = encryptedIndexTable2[expand2];
            ciphertexts.add(ciphertext1);
            ciphertexts.add(ciphertext2);
            i++;
        }
        return ciphertexts;
    }

    public SEScheme getSeScheme() {
        return seScheme;
    }

    public int getNumberOfDummyValues() {
        return numberOfDummyValues;
    }

    public int getNumberOfDummyCT() {
        return numberOfDummyCT;
    }
}
