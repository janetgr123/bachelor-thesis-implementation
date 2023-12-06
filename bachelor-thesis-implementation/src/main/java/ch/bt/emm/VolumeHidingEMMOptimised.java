package ch.bt.emm;

import ch.bt.crypto.CastingHelpers;
import ch.bt.crypto.DPRF;
import ch.bt.model.*;
import ch.bt.model.Label;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexTables;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.searchtoken.SearchTokenBytes;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

/** SSE scheme from Patel et al. (2019) With improved communication using delegatable PRFs */
public class VolumeHidingEMMOptimised extends VolumeHidingEMM {

    public VolumeHidingEMMOptimised(final int securityParameter, final double alpha)
            throws GeneralSecurityException {
        super(securityParameter, alpha);
    }

    @Override
    public SearchToken trapdoor(final Label searchLabel)
            throws GeneralSecurityException, IOException {
        return new SearchTokenBytes(DPRF.generateToken(getPrfKey(), searchLabel));
    }

    @Override
    public Set<Ciphertext> search(
            final SearchToken searchToken, final EncryptedIndex encryptedIndex)
            throws GeneralSecurityException, IOException {
        if (!(encryptedIndex instanceof EncryptedIndexTables)
                || !(searchToken instanceof SearchTokenBytes)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        Set<Ciphertext> ciphertexts = new HashSet<>();
        final var encryptedIndexTable1 = ((EncryptedIndexTables) encryptedIndex).getTable(0);
        final var encryptedIndexTable2 = ((EncryptedIndexTables) encryptedIndex).getTable(1);
        final var token = ((SearchTokenBytes) searchToken).token();
        final int tableSize = getTableSize();
        final int size = getMaxNumberOfValuesPerLabel();
        for (int i = 0; i < size; i++) {
            final var expand1 =
                    CastingHelpers.fromByteArrayToHashModN(
                            DPRF.evaluateDPRF(token, i, 0), tableSize);
            final var expand2 =
                    CastingHelpers.fromByteArrayToHashModN(
                            DPRF.evaluateDPRF(token, i, 1), tableSize);
            ciphertexts.add(encryptedIndexTable1[expand1]);
            ciphertexts.add(encryptedIndexTable2[expand2]);
        }
        return ciphertexts;
    }
}
