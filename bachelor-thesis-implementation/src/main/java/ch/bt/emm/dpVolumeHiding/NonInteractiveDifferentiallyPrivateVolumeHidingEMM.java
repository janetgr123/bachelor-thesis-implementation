package ch.bt.emm.dpVolumeHiding;

import ch.bt.crypto.*;
import ch.bt.emm.EMM;
import ch.bt.emm.volumeHiding.VolumeHidingEMMUtils;
import ch.bt.model.encryptedindex.*;
import ch.bt.model.multimap.*;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.searchtoken.SearchTokenBytes;
import ch.bt.model.searchtoken.SearchTokenBytesKeys;
import ch.bt.model.searchtoken.SearchTokenKeys;

import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class implements a Non-Interactive Differentially Private Volume-Hiding EMM scheme that
 * stores a lookup table on server side
 *
 * @author Janet Greutmann
 */
public class NonInteractiveDifferentiallyPrivateVolumeHidingEMM implements EMM {
    /** correction factor for the laplace distribution sampling */
    private final int correctionFactor;

    /** the privacy budget for differential privacy */
    private final double epsilon;

    /** Factor to calculate table size for Cuckoo Hashing */
    private final double alpha;

    /** the stash for the Cuckoo Hashing */
    private Stack<Ciphertext> stash;

    /** Symmetric encryption scheme */
    private final SEScheme seScheme;

    /** The secret key for the PRF */
    private final SecretKey prfKey;

    /** the size of the tables used for the Cuckoo Hashing */
    private int tableSize;

    /** the maximum number of values per label (used for padding) */
    private int maxNumberOfValuesPerLabel = 0;

    /** the number of dummy entries in the encrypted tables */
    private int numberOfDummyValues;

    /** the key dependent laplacian distribution */
    private final KeyDependentLaplaceDistribution laplaceDistribution;

    private Integer responsePadding;

    private final SecretKey lookupTableKey;

    private final Map<SecretKey, AESSEScheme> schemes = new HashMap<>();

    public NonInteractiveDifferentiallyPrivateVolumeHidingEMM(
            final int securityParameter, final double epsilon, final double alpha, final double t)
            throws GeneralSecurityException {
        final var keys = this.setup(securityParameter);
        this.prfKey = keys.get(0);
        this.lookupTableKey = keys.get(2);
        this.seScheme = new AESSEScheme(keys.get(1));
        this.alpha = alpha;
        this.epsilon = epsilon;
        this.laplaceDistribution = new KeyDependentLaplaceDistribution(0, 2 / epsilon);
        this.correctionFactor = (int) Math.ceil(2 * t / epsilon);
    }

    /**
     * Determines and sets the size of the padding
     *
     * @param multiMap the multimap containing the plaintext data
     */
    private void setMaxNumberOfValuesPerLabel(final Map<Label, Set<Plaintext>> multiMap) {
        final var keys = multiMap.keySet();
        for (final var key : keys) {
            final var num = multiMap.get(key).size();
            if (num > maxNumberOfValuesPerLabel) {
                maxNumberOfValuesPerLabel = num;
            }
        }
    }

    /**
     * @param securityParameter the length of the keys in bits
     * @return two secret keys, one for the PRF and one for the symmetric encryption scheme
     * @throws GeneralSecurityException
     */
    @Override
    public List<SecretKey> setup(int securityParameter) throws GeneralSecurityException {
        final var key1 = CryptoUtils.generateKeyWithHMac(securityParameter);
        final var key2 = CryptoUtils.generateKeyForAES(securityParameter);
        final var key3 = CryptoUtils.generateKeyWithHMac(securityParameter);
        return List.of(key1, key2, key3);
    }

    /**
     * @param multiMap the plaintext data stored in a multimap
     * @return the encrypted index of the multimap, including a lookup table for sanitized noise:
     *     response-revealing emm scheme Pi_bas from <a
     *     href="http://dx.doi.org/10.14722/ndss.2014.23264">Cash et al.</a>
     * @throws GeneralSecurityException
     */
    @Override
    public EncryptedIndex buildIndex(final Map<Label, Set<Plaintext>> multiMap)
            throws GeneralSecurityException, IOException {
        final int numberOfValues = VolumeHidingEMMUtils.getNumberOfValues(multiMap);
        this.tableSize = (int) Math.round((1 + alpha) * numberOfValues);

        // determine padding
        setMaxNumberOfValuesPerLabel(multiMap);

        /*
         * Cuckoo Hashing
         */
        final var encryptedIndexWithStash =
                VolumeHidingEMMUtils.calculateEncryptedIndexAndStash(
                        tableSize, numberOfValues, multiMap, prfKey, seScheme);

        final var encryptedIndex = encryptedIndexWithStash.encryptedIndex();
        this.stash = encryptedIndexWithStash.stash();
        this.numberOfDummyValues = encryptedIndexWithStash.numberOfDummyValues() * 32 * 2;

        /*
         * lookup table
         */
        final var lookup = new HashMap<Label, Ciphertext>();
        final var keys = multiMap.keySet();
        for (final var label : keys) {
            final var noise = laplaceDistribution.sample(label.label());
            if (correctionFactor + noise <= 0) {
                throw new RuntimeException("truncation error with noise " + noise);
            }
            var numberOfValuesWithNoise =
                    (int) (multiMap.get(label).size() + correctionFactor + noise);
            final var key1 =
                    new SecretKeySpec(
                            CryptoUtils.calculateHmac256(
                                    lookupTableKey,
                                    Arrays.concatenate(new byte[] {1}, label.label())),
                            "HMacSHA256");
            final var key2 =
                    new SecretKeySpec(
                            CryptoUtils.calculateHmac256(
                                    lookupTableKey,
                                    Arrays.concatenate(new byte[] {2}, label.label())),
                            "HMacSHA256");
            final var encryptionScheme = new AESSEScheme(key2);
            schemes.put(key2, encryptionScheme);
            lookup.put(
                    new Label(
                            CryptoUtils.calculateHmac256(
                                    key1, CastingHelpers.fromIntToByteArray(0))),
                    encryptionScheme.encrypt(
                            new Plaintext(
                                    CastingHelpers.fromIntToByteArray(numberOfValuesWithNoise))));
        }

        return new DifferentiallyPrivateEncryptedIndexTables(
                encryptedIndex, new LookupTable(lookup));
    }

    /**
     * @param label the search label in plaintext
     * @return a search token that enables access to the entry in the encrypted index and the lookup
     *     table that corresponds to the search label.
     * @throws GeneralSecurityException
     */
    @Override
    public SearchToken trapdoor(final Label label) throws GeneralSecurityException, IOException {
        final var key1 =
                new SecretKeySpec(
                        CryptoUtils.calculateHmac256(
                                lookupTableKey, Arrays.concatenate(new byte[] {1}, label.label())),
                        "HMacSHA256");
        final var key2 =
                new SecretKeySpec(
                        CryptoUtils.calculateHmac256(
                                lookupTableKey, Arrays.concatenate(new byte[] {2}, label.label())),
                        "HMacSHA256");
        final var token = new SearchTokenBytes(DPRF.generateToken(prfKey, label));
        return new SearchTokenBytesKeys(token, new SearchTokenKeys(key1, key2));
    }

    /**
     * @param searchToken the search token that has been generated with trapdoor(label)
     * @param encryptedIndex the encrypted index of the value tables
     * @return the set of ciphertexts that correspond to the label encrypted in the token
     */
    @Override
    public Set<Ciphertext> search(
            final SearchToken searchToken, final EncryptedIndex encryptedIndex)
            throws IOException, GeneralSecurityException {
        if (!(encryptedIndex instanceof DifferentiallyPrivateEncryptedIndexTables)
                || !(searchToken instanceof SearchTokenBytesKeys t)) {
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
        final var lookupTable =
                ((LookupTable)
                                ((DifferentiallyPrivateEncryptedIndexTables) encryptedIndex)
                                        .encryptedIndexCT())
                        .map();
        final var token = t.tokenBytes();
        final var keys = t.tokenKeys();
        final var encryptedValue =
                lookupTable.get(
                        new Label(
                                CryptoUtils.calculateHmac256(
                                        keys.key1(), CastingHelpers.fromIntToByteArray(0))));

        final var numberOfValues =
                CastingHelpers.fromByteArrayToInt(
                        schemes.get(keys.key2()).decrypt((CiphertextWithIV) encryptedValue).data());
        int i = 0;
        while (i < numberOfValues) {
            final var expand1 =
                    CastingHelpers.fromByteArrayToHashModN(
                            DPRF.evaluateDPRF(token.token(), i, 0), tableSize);
            final var expand2 =
                    CastingHelpers.fromByteArrayToHashModN(
                            DPRF.evaluateDPRF(token.token(), i, 1), tableSize);
            final var ciphertext1 = encryptedIndexTable1[expand1];
            final var ciphertext2 = encryptedIndexTable2[expand2];
            ciphertexts.add(ciphertext1);
            ciphertexts.add(ciphertext2);
            i++;
        }
        return ciphertexts;
    }

    /**
     * @param ciphertexts the set of ciphertexts that search2 found for a given token
     * @param searchLabel the search label in plaintext
     * @return the set of plaintexts that have been encrypted to those ciphertexts using the given
     *     ivs and the schemeKey
     */
    @Override
    public Set<Plaintext> result(Set<Ciphertext> ciphertexts, Label searchLabel)
            throws GeneralSecurityException {
        responsePadding = 0;
        final var dummies = new int[1];
        final var result =
                VolumeHidingEMMUtils.getPlaintexts(
                        ciphertexts, seScheme, searchLabel, stash, dummies);
        responsePadding = dummies[0];
        return result;
    }

    /**
     * Getter for the encryption scheme
     *
     * @return the encryption scheme instance
     */
    @Override
    public SEScheme getSeScheme() {
        return seScheme;
    }

    @Override
    public SecretKey getPrfKey() {
        return prfKey;
    }

    /**
     * Getter for the number of dummy entries in the encrypted index
     *
     * @return the number of dummy values in the value tables
     */
    @Override
    public int getNumberOfDummyValues() {
        return numberOfDummyValues;
    }

    @Override
    public int getResponsePadding() {
        return responsePadding;
    }
}
