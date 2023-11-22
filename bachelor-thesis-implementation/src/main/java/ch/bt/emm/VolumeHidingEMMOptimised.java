package ch.bt.emm;

import ch.bt.crypto.CryptoUtils;
import ch.bt.model.*;
import ch.bt.model.Label;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexTables;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.searchtoken.SearchTokenCiphertext;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.*;

/** SSE scheme from Patel et al. (2019) With improved communication using delegatable PRFs */
public class VolumeHidingEMMOptimised extends VolumeHidingEMM {
    private SecretKey key;

    public VolumeHidingEMMOptimised(final int securityParameter, final double alpha)
            throws GeneralSecurityException {
        super(securityParameter, alpha);
    }

    @Override
    public SearchToken trapdoor(final Label searchLabel)
            throws GeneralSecurityException, IOException {
        addSearchLabel(searchLabel);
        // TODO: DPRF!!
        key = CryptoUtils.generateKeyForAES(getSecurityParameter());
        final var encryptedLabel = CryptoUtils.cbcEncrypt(key, searchLabel.label());
        return new SearchTokenCiphertext(encryptedLabel);
    }

    @Override
    public Set<Ciphertext> search(
            final SearchToken searchToken, final EncryptedIndex encryptedIndex)
            throws GeneralSecurityException {
        if (!(encryptedIndex instanceof EncryptedIndexTables)
                || !(searchToken instanceof SearchTokenCiphertext)) {
            throw new IllegalArgumentException(
                    "types of encrypted index or search token are not matching");
        }
        Set<Ciphertext> ciphertexts = new HashSet<>();
        final var encryptedIndexTable1 = ((EncryptedIndexTables) encryptedIndex).getTable(0);
        final var encryptedIndexTable2 = ((EncryptedIndexTables) encryptedIndex).getTable(1);
        final var token = ((SearchTokenCiphertext) searchToken).token();
        // TODO: DPRF!!!
        final var label = CryptoUtils.cbcDecrypt(key, token);
        final var expand1 = new BigInteger(CryptoUtils.calculateSha3Digest(label)).intValue();
        final var expand2 = new BigInteger(CryptoUtils.calculateSha3Digest(label)).intValue();
        ciphertexts.add(encryptedIndexTable1[expand1]);
        ciphertexts.add(encryptedIndexTable2[expand2]);
        return ciphertexts;
    }
}
