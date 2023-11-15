package ch.bt.emm;

import ch.bt.model.*;

import java.security.SecureRandom;
import java.util.*;

/** SSE scheme from Patel et al. (2019) With improved communication using delegatable PRFs */
public class VolumeHidingEMMOptimised extends VolumeHidingEMM {

    public VolumeHidingEMMOptimised(
            final SecureRandom secureRandom,
            final SecureRandom secureRandomSE,
            final int securityParameter,
            final int alpha,
            final Map<Label, Set<Value>> multiMap) {
        super(secureRandom, secureRandomSE, securityParameter, alpha, multiMap);
    }

    /**
     * @param label
     * @return
     */
    @Override
    public SearchToken trapdoor(final Label label) {
        final var hash = getHash();
        final var labelHash = hash.hash(label.getLabel());
        return new SearchTokenBytes(labelHash);
    }

    /**
     * @param searchToken
     * @param encryptedIndex
     * @return
     */
    @Override
    public Set<PairLabelValue> search(final SearchToken searchToken, final EncryptedIndex encryptedIndex) {
        if (!(encryptedIndex instanceof EncryptedIndexTables)
                || !(searchToken instanceof SearchTokenBytes)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        Set<PairLabelValue> ciphertexts = new HashSet<>();
        final var encryptedIndexTable1 = ((EncryptedIndexTables) encryptedIndex).getTable(0);
        final var encryptedIndexTable2 = ((EncryptedIndexTables) encryptedIndex).getTable(1);
        final var token = ((SearchTokenBytes) searchToken).getToken();
        final var hashedToken = Math.floorMod(Arrays.hashCode(token), getTableSize());
        ciphertexts.add(encryptedIndexTable1[hashedToken]);
        ciphertexts.add(encryptedIndexTable2[hashedToken]);
        return ciphertexts;
    }
}
