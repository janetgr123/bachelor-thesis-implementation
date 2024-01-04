package ch.bt.emm.volumeHiding;

import ch.bt.crypto.CastingHelpers;
import ch.bt.crypto.DPRF;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexTables;
import ch.bt.model.multimap.Ciphertext;
import ch.bt.model.multimap.Label;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.searchtoken.SearchTokenBytes;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

/**
 * This class implements the Optimised Volume Hiding SSE scheme from <a
 * href="https://doi.org/10.1145/3319535.3354213">Patel et al.</a>
 *
 * @author Janet Greutmann
 */
public class VolumeHidingEMMOptimised extends VolumeHidingEMM {

    public VolumeHidingEMMOptimised(final int securityParameter, final double alpha)
            throws GeneralSecurityException {
        super(securityParameter, alpha);
    }

    /**
     * @param searchLabel the search label in plaintext
     * @return a search token that enables access to the entries in the encrypted index that
     *     correspond to the search label. The search token is generated using DPRFs and thus can be
     *     extended which reduces the communication overhead.
     * @throws GeneralSecurityException
     */
    @Override
    public SearchToken trapdoor(final Label searchLabel)
            throws GeneralSecurityException, IOException {
        return new SearchTokenBytes(DPRF.generateToken(getPrfKey(), searchLabel));
    }

    /**
     * @param searchToken the search token prefix that has been generated with trapdoor
     * @param encryptedIndex the encrypted index
     * @return the set of ciphertexts that correspond to the labels encrypted in the extended token
     * @throws GeneralSecurityException
     */
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
            final var ciphertext1 = encryptedIndexTable1[expand1];
            final var ciphertext2 = encryptedIndexTable2[expand2];
            ciphertexts.add(ciphertext1);
            ciphertexts.add(ciphertext2);
        }
        return ciphertexts;
    }
}
