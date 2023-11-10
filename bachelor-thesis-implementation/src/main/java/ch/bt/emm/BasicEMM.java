package ch.bt.emm;

import ch.bt.crypto.*;
import ch.bt.model.*;

import org.bouncycastle.crypto.params.KeyParameter;

import java.security.SecureRandom;
import java.util.*;

/**
 * based on the SSE scheme Pi_bas from Cash et al. 2014
 */
public class BasicEMM implements EMM {

    private static final int CAPACITY = 1000; // TODO: set
    private final SecureRandom secureRandom;

    private final HKDFDerivator keyDerivator = new HKDFDerivator();

    private final SecretKey key;

    private final SEScheme SEScheme;

    private final Hash hash;

    public BasicEMM(final SecureRandom secureRandom, final int securityParameter) {
        this.secureRandom = secureRandom;
        this.key = this.setup(securityParameter);
        if (this.key instanceof SecretKeyPair) {
            final var keyPair = this.key.getKey().getKeys();
            hash = new HMacHash(new KeyParameter(keyPair.get(0).getBytes()));
            //hash = new SHA256Hash(new KeyParameter(keyPair.get(0).getBytes()));
            SEScheme = new AESSEScheme(secureRandom, keyPair.get(1));
        } else {
            hash = null;
            SEScheme = null;
        }
    }

    /**
     * @param securityParameter
     * @return
     */
    @Override
    public SecretKey setup(int securityParameter) {
        final var masterKey = new KeyGenerator(secureRandom, securityParameter).generateKey();
        final var key1 = keyDerivator.deriveKeyFrom(masterKey, null);
        final var key2 = keyDerivator.deriveKeyFrom(masterKey, null);
        return new SecretKeyPair(key1, key2);
    }

    /**
     * @param multiMap
     * @return
     */
    @Override
    public Map<EncryptedLabel, EncryptedValue> buildIndex(Map<PlaintextLabel, Set<PlaintextValue>> multiMap) {
        Map<EncryptedLabel, EncryptedValue> encryptedIndex = new HashMap<>();
        final var labels = multiMap.keySet();
        for (PlaintextLabel label : labels) {
            final var valuesOfLabel = multiMap.get(label);
            for (PlaintextValue value : valuesOfLabel) {
                final EncryptedLabel encryptedLabel = new EncryptedLabel(hash.hash(label.getLabel()));
                final EncryptedValue encryptedValue = new EncryptedValue(SEScheme.encrypt(value.getValue()));
                encryptedIndex.put(encryptedLabel, encryptedValue);
            }
        }
        return encryptedIndex;
    }

    /**
     * @param label
     * @return
     */
    @Override
    public SearchToken trapdoor(final Label label) {
        return new SearchToken(hash.hash(label.getLabel()));

    }

    /**
     * @param searchToken
     * @param encryptedIndex
     * @return
     */
    @Override
    public Set<Value> search(final SearchToken searchToken, final Map<EncryptedLabel, EncryptedValue> encryptedIndex) {
        Set<Value> encryptedValues = new HashSet<>();
        final var matchingLabels = encryptedIndex.keySet().stream().filter(el -> el.getLabel().equals(hash.hash(searchToken.token()))).toList();
        for(Label l : matchingLabels){
            encryptedValues.add(encryptedIndex.get(l));
        }
        return encryptedValues;
    }

    /**
     * @param values
     * @return
     */
    @Override
    public Set<Value> result(final Set<Value> values) {
        Set<Value> plaintextValues = new HashSet<>();
        if (key instanceof SecretKeyPair) {
            values.stream().forEach(encryptedValue -> {
                plaintextValues.add(new PlaintextValue(SEScheme.decrypt(encryptedValue.getValue())));
            });
        }
        return plaintextValues;
    }

}
