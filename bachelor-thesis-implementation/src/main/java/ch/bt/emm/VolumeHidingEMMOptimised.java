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

    @Override
    public SearchToken trapdoor(final Label label) {
        final var hash = getHash();
        final var labelHash = hash.hash(label.label());
        return new SearchTokenBytes(labelHash);
    }

    @Override
    public Set<Pair> search(final SearchToken searchToken, final EncryptedIndex encryptedIndex) {
        if (!(encryptedIndex instanceof EncryptedIndexTables)
                || !(searchToken instanceof SearchTokenBytes)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        Set<Pair> ciphertexts = new HashSet<>();
        final var encryptedIndexTable1 = ((EncryptedIndexTables) encryptedIndex).getTable(0);
        final var encryptedIndexTable2 = ((EncryptedIndexTables) encryptedIndex).getTable(1);
        final var token = ((SearchTokenBytes) searchToken).token();
        final var hashedToken = Math.floorMod(Arrays.hashCode(token), getTableSize());
        ciphertexts.add(encryptedIndexTable1[hashedToken]);
        ciphertexts.add(encryptedIndexTable2[hashedToken]);
        return ciphertexts;
    }
}
