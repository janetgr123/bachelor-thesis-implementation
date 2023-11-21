package ch.bt.emm;

import ch.bt.crypto.CryptoUtils;
import ch.bt.model.*;
import ch.bt.model.Label;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexTables;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.searchtoken.SearchTokenBytes;

import java.security.GeneralSecurityException;
import java.util.*;

/** SSE scheme from Patel et al. (2019) With improved communication using delegatable PRFs */
public class VolumeHidingEMMOptimised extends VolumeHidingEMM {

    public VolumeHidingEMMOptimised(final int securityParameter, final int alpha)
            throws GeneralSecurityException {
        super(securityParameter, alpha);
    }

    @Override
    public SearchToken trapdoor(final Label searchLabel) throws GeneralSecurityException {
        setSearchLabel(searchLabel);
        final var labelHash = CryptoUtils.calculateSha3Digest(searchLabel.label());
        return new SearchTokenBytes(labelHash);
    }

    @Override
    public Set<Ciphertext> search(
            final SearchToken searchToken, final EncryptedIndex encryptedIndex) {
        if (!(encryptedIndex instanceof EncryptedIndexTables)
                || !(searchToken instanceof SearchTokenBytes)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        Set<Ciphertext> ciphertexts = new HashSet<>();
        final var encryptedIndexTable1 = ((EncryptedIndexTables) encryptedIndex).getTable(0);
        final var encryptedIndexTable2 = ((EncryptedIndexTables) encryptedIndex).getTable(1);
        final var token = ((SearchTokenBytes) searchToken).token();
        final var hashedToken = Math.floorMod(Arrays.hashCode(token), getTableSize());
        ciphertexts.add(encryptedIndexTable1[hashedToken]);
        ciphertexts.add(encryptedIndexTable2[hashedToken]);
        return ciphertexts;
    }
}
