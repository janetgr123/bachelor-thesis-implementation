package ch.bt.emm;

import ch.bt.crypto.SecretKey;
import ch.bt.model.*;

import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;

/**
 * SSE scheme from Patel et al. (2019)
 */

// TODO: implement
public class VolumeHidingEMM implements EMM {

    private final SecureRandom secureRandom;

    public VolumeHidingEMM(final SecureRandom secureRandom, final int securityParameter){
        this.secureRandom = secureRandom;
    }

    /**
     * @param securityParameter 
     * @return
     */
    @Override
    public SecretKey setup(int securityParameter) {
        return null;
    }

    /**
     * @param multiMap 
     * @return
     */
    @Override
    public Map<EncryptedLabel, EncryptedValue> buildIndex(Map<PlaintextLabel, Set<PlaintextValue>> multiMap) {
        return null;
    }

    /**
     * @param label
     * @return
     */
    @Override
    public SearchToken trapdoor(Label label) {
        return null;
    }

    /**
     * @param searchToken 
     * @param encryptedIndex
     * @return
     */
    @Override
    public Set<Value> search(SearchToken searchToken, Map<EncryptedLabel, EncryptedValue> encryptedIndex) {
        return null;
    }

    /**
     * @param values
     * @return
     */
    @Override
    public Set<Value> result(Set<Value> values) {
        return null;
    }
}
