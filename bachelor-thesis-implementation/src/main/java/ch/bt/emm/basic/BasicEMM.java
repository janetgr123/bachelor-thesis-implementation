package ch.bt.emm.basic;

import ch.bt.crypto.*;
import ch.bt.emm.EMM;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexMap;
import ch.bt.model.multimap.Ciphertext;
import ch.bt.model.multimap.CiphertextWithIV;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.searchtoken.SearchTokenBytes;

import java.security.GeneralSecurityException;
import java.util.*;

import javax.crypto.SecretKey;

/**
 * This class is based on the SSE scheme Pi_bas from <a
 * href="http://dx.doi.org/10.14722/ndss.2014.23264">Cash et al.</a> The implementation of <a
 * href="https://github.com/cloudsecuritygroup/ers-attacks">Falzon et al.</a> in Python has been
 * used as a reference code base.
 *
 * @author Janet Greutmann
 */
public class BasicEMM implements EMM {
    /** the symmetric encryption scheme */
    private final SEScheme seScheme;

    /** the secret key used for HMAC hashing (which implements the PRF) */
    private final SecretKey hmacKey;

    public BasicEMM(final int securityParameter) throws GeneralSecurityException {
        final var keys = this.setup(securityParameter);
        this.hmacKey = keys.get(0);
        final var aesKey = keys.get(1);
        seScheme = new AESSEScheme(aesKey);
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
        return List.of(key1, key2);
    }

    /**
     * @param multiMap the plaintext data stored in a multimap
     * @return the encrypted index of the multimap with encryptedLabel = SHA3(HMAC(prfKey, label) ||
     *     k), k in [0, |multimap[label]|] and encryptedValue = Enc(schemeKey, value).
     * @throws GeneralSecurityException
     */
    @Override
    public EncryptedIndex buildIndex(Map<Label, Set<Plaintext>> multiMap)
            throws GeneralSecurityException {
        Map<Label, CiphertextWithIV> encryptedIndex = new HashMap<>();
        final var labels = multiMap.keySet();
        for (final var label : labels) {
            int counter = 0;
            final var valuesOfLabel = multiMap.get(label);
            final var token = CryptoUtils.calculateHmac(hmacKey, label.label());
            for (final var value : valuesOfLabel) {
                final var tokenAndCounter = getTokenAndCounter(counter, token);
                final var encryptedLabel =
                        new Label(CryptoUtils.calculateSha3Digest(tokenAndCounter));
                final var encryptedValue = seScheme.encrypt(value);
                encryptedIndex.put(encryptedLabel, encryptedValue);
                counter++;
            }
        }
        return new EncryptedIndexMap(encryptedIndex);
    }

    /**
     * @param searchLabel the search label in plaintext
     * @return a search token that enables access to the entry in the encrypted index that
     *     corresponds to the search label.
     * @throws GeneralSecurityException
     */
    @Override
    public SearchToken trapdoor(final Label searchLabel) throws GeneralSecurityException {
        return new SearchTokenBytes(CryptoUtils.calculateHmac(hmacKey, searchLabel.label()));
    }

    /**
     * @param searchToken the search token that has been generated with trapdoor
     * @param encryptedIndex the encrypted index
     * @return the set of ciphertexts that correspond to the label encrypted in the token
     * @throws GeneralSecurityException
     */
    @Override
    public Set<Ciphertext> search(
            final SearchToken searchToken, final EncryptedIndex encryptedIndex)
            throws GeneralSecurityException {
        if (!(encryptedIndex instanceof EncryptedIndexMap)
                || !(searchToken instanceof SearchTokenBytes)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        final var encryptedIndexMap = ((EncryptedIndexMap) encryptedIndex).map();
        Set<Ciphertext> encryptedValues = new HashSet<>();
        int counter = 0;
        while (true) {
            final var tokenAndCounter =
                    getTokenAndCounter(counter, ((SearchTokenBytes) searchToken).token());
            final var encryptedLabel = new Label(CryptoUtils.calculateSha3Digest(tokenAndCounter));
            if(encryptedIndexMap.containsKey(encryptedLabel)) {
               encryptedValues.add(encryptedIndexMap.get(encryptedLabel));
            /*
            final var matchingLabels =
                    encryptedIndexMap.keySet().stream().filter(encryptedLabel::equals).toList();
            if (matchingLabels.size() == 1) {
                final var matchingValue = encryptedIndexMap.get(matchingLabels.get(0));
                encryptedValues.add(matchingValue);

             */
            } else {
                break;
            }
            counter++;
        }
        return encryptedValues;
    }

    /**
     * @param ciphertextWithIVS the set of ciphertexts that search found for a given token
     * @param searchLabel the search label in plaintext
     * @return the set of plaintexts that have been encrypted to those ciphertexts using the given
     *     ivs and the schemeKey
     */
    @Override
    public Set<Plaintext> result(final Set<Ciphertext> ciphertextWithIVS, final Label searchLabel) {
        Set<Plaintext> plaintextValues = new HashSet<>();
        ciphertextWithIVS.forEach(
                encryptedValue -> {
                    try {
                        plaintextValues.add(seScheme.decrypt((CiphertextWithIV) encryptedValue));
                    } catch (GeneralSecurityException e) {
                        throw new RuntimeException(e);
                    }
                });
        return plaintextValues;
    }

    /**
     * @param counter the current counter number <= 0
     * @param token the token as a byte array
     * @return token || counter as a byte array
     */
    private String getTokenAndCounter(final int counter, final byte[] token) {
        return Arrays.toString(token).concat(String.valueOf(counter));
    }

    /**
     * Getter for the encryption scheme
     *
     * @return the encryption scheme instance
     */
    public SEScheme getSeScheme() {
        return this.seScheme;
    }

    /**
     * Getter for the number of dummy entries in the encrypted index
     *
     * @return 0 because in this scheme are none
     */
    public int getNumberOfDummyValues() {
        return 0;
    }

    /**
     * Getter for the PRF key
     *
     * @return the prf key of this instance of the scheme
     */
    @Override
    public SecretKey getPrfKey() {
        return hmacKey;
    }
}
