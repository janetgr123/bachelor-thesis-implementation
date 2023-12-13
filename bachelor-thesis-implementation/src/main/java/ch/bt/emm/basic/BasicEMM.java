package ch.bt.emm.basic;

import ch.bt.crypto.*;
import ch.bt.emm.EMM;
import ch.bt.model.multimap.Ciphertext;
import ch.bt.model.multimap.CiphertextWithIV;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexMap;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.searchtoken.SearchTokenBytes;

import java.security.GeneralSecurityException;
import java.util.*;

import javax.crypto.SecretKey;

/** based on the SSE scheme Pi_bas from Cash et al. 2014 */
public class BasicEMM implements EMM {
    private final SEScheme seScheme;
    private final SecretKey hmacKey;

    public BasicEMM(final int securityParameter) throws GeneralSecurityException {
        final var keys = this.setup(securityParameter);
        this.hmacKey = keys.get(0);
        seScheme = new AESSEScheme(keys.get(1));
    }

    @Override
    public List<SecretKey> setup(int securityParameter) throws GeneralSecurityException {
        final var key1 = CryptoUtils.generateKeyWithHMac(securityParameter);
        final var key2 = CryptoUtils.generateKeyForAES(securityParameter);
        return List.of(key1, key2);
    }

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

    @Override
    public SearchToken trapdoor(final Label searchLabel) throws GeneralSecurityException {
        return new SearchTokenBytes(CryptoUtils.calculateHmac(hmacKey, searchLabel.label()));
    }

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
            final var matchingLabels =
                    encryptedIndexMap.keySet().stream().filter(encryptedLabel::equals).toList();
            if (matchingLabels.size() == 1) {
                encryptedValues.add(encryptedIndexMap.get(matchingLabels.get(0)));
            } else {
                break;
            }
            counter++;
        }
        return encryptedValues;
    }

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

    private String getTokenAndCounter(final int counter, final byte[] token) {
        return Arrays.toString(token).concat(String.valueOf(counter));
    }

    public SEScheme getSeScheme() {
        return this.seScheme;
    }

    public int getNumberOfDummyValues() {
        return 0;
    }
}
