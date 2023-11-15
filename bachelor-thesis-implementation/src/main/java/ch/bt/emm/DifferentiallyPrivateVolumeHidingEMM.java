package ch.bt.emm;

import ch.bt.model.*;

import org.apache.commons.math3.distribution.LaplaceDistribution;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

/** SSE scheme from Patel et al. (2019) */
public class DifferentiallyPrivateVolumeHidingEMM extends VolumeHidingEMM {

    private static final int correctionFactor = 5610;

    private final double epsilon;
    private Stack<PairLabelNumberValues> counterStash;

    public DifferentiallyPrivateVolumeHidingEMM(
            final SecureRandom secureRandom,
            final SecureRandom secureRandomSE,
            final int securityParameter,
            final double epsilon,
            final int alpha,
            final Map<Label, Set<Value>> multiMap) {
        super(secureRandom, secureRandomSE, securityParameter, alpha, multiMap);
        this.epsilon = epsilon;
    }

    @Override
    public EncryptedIndex buildIndex() {
        final var encryptedIndex = super.buildIndex();
        final int tableSize = getTableSize();
        final var multiMap = getMultiMap();
        final var maxStashSize = getMaxStashSize();
        final var hash = getHash();
        final var seScheme = getSeScheme();

        final PairLabelNumberValues[] counterTable1 = new PairLabelNumberValues[tableSize];
        final PairLabelNumberValues[] counterTable2 = new PairLabelNumberValues[tableSize];
        final Stack<PairLabelNumberValues> counterStash = new Stack<>();
        VolumeHidingEMMUtils.doCuckooHashingWithStashCT(
                maxStashSize,
                counterTable1,
                counterTable2,
                multiMap,
                counterStash,
                hash,
                tableSize);
        VolumeHidingEMMUtils.fillEmptyValues(counterTable1);
        VolumeHidingEMMUtils.fillEmptyValues(counterTable2);
        this.counterStash = counterStash;

        final PairLabelNumberValues[] encryptedCounterTable1 = new PairLabelNumberValues[tableSize];
        final PairLabelNumberValues[] encryptedCounterTable2 = new PairLabelNumberValues[tableSize];
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
    public SearchToken trapdoor(final Label label) {
        final var hash = getHash();
        final var counterLabelHash =
                hash.hash(
                        org.bouncycastle.util.Arrays.concatenate(
                                BigInteger.valueOf(VolumeHidingEMMUtils.CT).toByteArray(),
                                label.label()));
        return new SearchTokenBytes(counterLabelHash);
    }

    public SearchToken trapdoor(final Label label, final Set<Pair> pairs) {
        final var encryptedLabel = new Label(getSeScheme().encrypt(label.label()));
        final var matchingEntries =
                pairs.stream()
                        .map(PairLabelNumberValues.class::cast)
                        .filter(el -> el.label().equals(encryptedLabel))
                        .count();
        final var matchingEntriesInStash =
                counterStash.stream().filter(el -> el.label().equals(encryptedLabel)).count();
        final var mu = 0;
        final var beta = 2 / epsilon;
        final var laplaceDistribution = new LaplaceDistribution(mu, beta);
        final var noise = laplaceDistribution.sample();
        final var numberOfValuesWithNoise =
                (int) (matchingEntries + matchingEntriesInStash + correctionFactor + noise);
        final var hash = getHash();
        final var token = hash.hash(label.label());
        return new SearchTokenIntBytes(numberOfValuesWithNoise, token);
    }

    @Override
    public Set<Pair> search(final SearchToken searchToken, final EncryptedIndex encryptedIndex) {
        if (!(encryptedIndex instanceof DifferentiallyPrivateEncryptedIndexTables)
                || !(searchToken instanceof SearchTokenBytes)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        Set<Pair> ciphertexts = new HashSet<>();
        final var encryptedCounterTable =
                ((DifferentiallyPrivateEncryptedIndexTables) encryptedIndex).getCounterTable(0);
        final var encryptedCounterTable2 =
                ((DifferentiallyPrivateEncryptedIndexTables) encryptedIndex).getCounterTable(1);
        final var token = ((SearchTokenBytes) searchToken).token();
        final var hashedToken = Math.floorMod(Arrays.hashCode(token), getTableSize());
        ciphertexts.add(encryptedCounterTable[hashedToken]);
        ciphertexts.add(encryptedCounterTable2[hashedToken]);
        return ciphertexts;
    }

    public Set<Pair> search2(final SearchToken searchToken, final EncryptedIndex encryptedIndex) {
        if (!(encryptedIndex instanceof DifferentiallyPrivateEncryptedIndexTables)
                || !(searchToken instanceof SearchTokenIntBytes token)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        Set<Pair> ciphertexts = new HashSet<>();
        final var encryptedIndexTables =
                ((DifferentiallyPrivateEncryptedIndexTables) encryptedIndex)
                        .getEncryptedIndexTables();
        if (!(encryptedIndexTables instanceof EncryptedIndexTables tables)) {
            throw new IllegalArgumentException("types of encrypted index tables are not matching");
        }
        final var encryptedIndexTable1 = tables.getTable(0);
        final var encryptedIndexTable2 = tables.getTable(1);
        final var numberOfValues = token.token();
        final var hashedToken = Math.floorMod(Arrays.hashCode(token.token2()), getTableSize());
        int i = 0;
        while (i < numberOfValues) {
            ciphertexts.add(encryptedIndexTable1[hashedToken]);
            ciphertexts.add(encryptedIndexTable2[hashedToken]);
            i++;
        }
        return ciphertexts;
    }
}
