package ch.bt.emm;

import ch.bt.crypto.*;
import ch.bt.model.*;

import org.bouncycastle.crypto.params.KeyParameter;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

/** based on the SSE scheme Pi_bas from Cash et al. 2014 */
public class BasicEMM implements EMM {
    private final SecureRandom secureRandom;

    private final HKDFDerivator keyDerivator;

    private final SEScheme seScheme;

    private final Map<Label, Set<Value>> multiMap;

    private final Hash hMac;

    private final Hash hash;

    public BasicEMM(
            final SecureRandom secureRandom,
            final int securityParameter,
            final Map<Label, Set<Value>> multiMap) {
        this.secureRandom = secureRandom;
        this.keyDerivator = new HKDFDerivator(securityParameter);
        this.multiMap = multiMap;
        final var key = this.setup(securityParameter);
        final var keyPair = key.getKey().keys();
        hMac = new HMacHash(new KeyParameter(keyPair.get(0).getBytes()));
        hash = new SHA512Hash();
        seScheme = new AESSEScheme(secureRandom, keyPair.get(1));
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

    @Override
    public EncryptedIndex buildIndex() {
        Map<Label, Value> encryptedIndex = new HashMap<>();
        final var labels = multiMap.keySet();
        for (Label label : labels) {
            int counter = 0;
            final var valuesOfLabel = multiMap.get(label);
            final var token = hMac.hash(label.label());
            for (Value value : valuesOfLabel) {
                final var tokenAndCounter = getTokenAndCounter(counter, token);
                final var encryptedLabel = new Label(hash.hash(tokenAndCounter));
                final var encryptedValue = new Value(seScheme.encrypt(value.value()));
                encryptedIndex.put(encryptedLabel, encryptedValue);
                counter++;
            }
        }
        return new EncryptedIndexMap(encryptedIndex);
    }

    /**
     * @param label
     * @return
     */
    @Override
    public SearchToken trapdoor(final Label label) {
        return new SearchTokenBytes(hMac.hash(label.label()));
    }

    /**
     * @param searchToken
     * @param encryptedIndex
     * @return
     */
    @Override
    public Set<Pair> search(final SearchToken searchToken, final EncryptedIndex encryptedIndex) {
        if (!(encryptedIndex instanceof EncryptedIndexMap)
                || !(searchToken instanceof SearchTokenBytes)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        final var encryptedIndexMap = ((EncryptedIndexMap) encryptedIndex).map();
        Set<Pair> encryptedValues = new HashSet<>();
        int counter = 0;
        while (true) {
            final var tokenAndCounter =
                    getTokenAndCounter(counter, ((SearchTokenBytes) searchToken).token());
            final var encryptedLabel = hash.hash(tokenAndCounter);
            final var matchingLabels =
                    encryptedIndexMap.keySet().stream()
                            .filter(el -> Arrays.equals(el.label(), encryptedLabel))
                            .toList();
            if (matchingLabels.size() == 1) {
                encryptedValues.add(
                        new PairLabelValue(
                                new Label(new byte[0]),
                                encryptedIndexMap.get(matchingLabels.get(0))));
            } else {
                break;
            }
            counter++;
        }
        return encryptedValues;
    }

    /**
     * @param values
     * @param label
     * @return
     */
    @Override
    public Set<Value> result(final Set<Pair> values, final Label label) {
        Set<Value> plaintextValues = new HashSet<>();
        values.forEach(
                encryptedValue -> {
                    if (!(encryptedValue instanceof PairLabelValue)) {
                        throw new IllegalArgumentException("type of values not matching.");
                    }
                    plaintextValues.add(
                            new Value(
                                    seScheme.decrypt(
                                            ((PairLabelValue) encryptedValue).value().value())));
                });
        return plaintextValues;
    }

    private byte[] getTokenAndCounter(final int counter, final byte[] token) {
        return org.bouncycastle.util.Arrays.concatenate(
                token, BigInteger.valueOf(counter).toByteArray());
    }

    public SEScheme getSeScheme() {
        return this.seScheme;
    }

    public Hash getHash() {
        return hash;
    }

    public Hash getHMac() {
        return hMac;
    }
}
