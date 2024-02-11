package ch.bt.emm.volumeHiding;

import ch.bt.crypto.AESSEScheme;
import ch.bt.crypto.CryptoUtils;
import ch.bt.crypto.SEScheme;
import ch.bt.emm.EMM;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexTable;
import ch.bt.model.multimap.*;
import ch.bt.model.searchtoken.SearchToken;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

import javax.crypto.SecretKey;

import static ch.bt.emm.volumeHiding.VolumeHidingXorEMMUtils.R;

public class VolumeHidingXorEMM implements EMM {
    /** Symmetric encryption scheme */
    private final SEScheme seScheme;

    /** The secret key for the PRF */
    private final SecretKey prfKey;

    /** the maximum number of values per label (used for padding) */
    private int maxNumberOfValuesPerLabel = 0;

    /** the number of dummy entries in the encrypted tables */
    private int numberOfDummyValues;

    private final int beta;

    private int ciphertextLength;

    public VolumeHidingXorEMM(final int securityParameter, final int beta)
            throws GeneralSecurityException {
        final var keys = this.setup(securityParameter);
        this.prfKey = keys.get(0);
        final var aesKey = keys.get(1);
        this.seScheme = new AESSEScheme(aesKey);
        this.beta = beta;
    }

    /**
     * @param securityParameter the length of the keys in bits
     * @return two secret keys, one for the PRF and one for the symmetric encryption scheme
     * @throws GeneralSecurityException
     */
    @Override
    public List<SecretKey> setup(final int securityParameter) throws GeneralSecurityException {
        final var key1 = CryptoUtils.generateKeyWithHMac(securityParameter);
        final var key2 = CryptoUtils.generateKeyForAES(securityParameter);
        return List.of(key1, key2);
    }

    @Override
    public EncryptedIndex buildIndex(Map<Label, Set<Plaintext>> multiMap)
            throws GeneralSecurityException, IOException {
        setMaxNumberOfValuesPerLabel(multiMap);
        final var stack = VolumeHidingXorEMMUtils.doMappingStep(prfKey, multiMap);
        final var emmSize = ((int) Math.floor(1.23 * multiMap.size())) + beta;
        final var table = new ArrayList<byte[]>(emmSize);
        stack.forEach(
                el -> {
                    final var list = new LinkedList<CiphertextWithIV>();
                    final var values = multiMap.get(el.pair().label());
                    values.forEach(
                            value -> {
                                try {
                                    list.add(seScheme.encrypt(value));
                                } catch (GeneralSecurityException e) {
                                    throw new RuntimeException(e);
                                }
                            });
                    while(list.size() < maxNumberOfValuesPerLabel){
                        try {
                            list.add(seScheme.encrypt(new Plaintext(VolumeHidingXorEMMUtils.drawRandomOfLength(el.pair().value().data().length))));
                        } catch (GeneralSecurityException e) {
                            throw new RuntimeException(e);
                        }
                    }
                    final int index = el.index();
                    final var ciphertext = list.stream().map(e -> org.bouncycastle.util.Arrays.concatenate(e.data(), e.iv())).reduce(new byte[0], Arrays::concatenate);
                    this.ciphertextLength = ciphertext.length;
                    table.set(index, ciphertext);
                    for (int t = 0; t < R; t++) {
                        try {
                            final var hash =
                                    VolumeHidingXorEMMUtils.calculateIndex(
                                            el.pair(), prfKey, t, multiMap.size());
                            if(hash != index){
                                if(table.get(hash) == null){
                                    table.set(hash, VolumeHidingXorEMMUtils.drawRandomOfLength(ciphertextLength));
                                }
                                table.set(index, VolumeHidingXorEMMUtils.XOR(table.get(index), table.get(hash)));
                            }
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                });
        table.forEach(el -> {
            if(el == null){
                table.set(table.indexOf(el), VolumeHidingXorEMMUtils.drawRandomOfLength(ciphertextLength));
            }
        });
        return new EncryptedIndexTable(table);
    }

    @Override
    public SearchToken trapdoor(Label searchLabel) throws GeneralSecurityException, IOException {
        return null;
    }

    @Override
    public Set<Ciphertext> search(SearchToken searchToken, EncryptedIndex encryptedIndex)
            throws GeneralSecurityException, IOException {
        return null;
    }

    @Override
    public Set<Plaintext> result(Set<Ciphertext> ciphertexts, Label searchLabel)
            throws GeneralSecurityException {
        return null;
    }

    @Override
    public int getNumberOfDummyValues() {
        return 0;
    }

    @Override
    public SecretKey getPrfKey() {
        return null;
    }

    @Override
    public SEScheme getSeScheme() {
        return null;
    } /**
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
}
