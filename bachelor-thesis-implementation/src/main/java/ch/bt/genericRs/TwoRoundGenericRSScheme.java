package ch.bt.genericRs;

import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.multimap.Ciphertext;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.searchtoken.SearchToken;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;

public interface TwoRoundGenericRSScheme {
    List<SecretKey> setup(final int securityParameter) throws GeneralSecurityException, IOException;

    EncryptedIndex buildIndex(final Map<Label, Set<Plaintext>> multiMap)
            throws GeneralSecurityException, IOException;

    List<SearchToken> trapdoor(final CustomRange q);

    List<SearchToken> trapdoor(final CustomRange q, final Set<Ciphertext> ciphertexts)
            throws GeneralSecurityException, IOException;

    Set<Ciphertext> search(
            final List<SearchToken> searchToken, final EncryptedIndex encryptedIndex);

    Set<Ciphertext> search2(
            final List<SearchToken> searchToken, final EncryptedIndex encryptedIndex)
            throws IOException;

    Set<Plaintext> result(final Set<Ciphertext> values, final CustomRange q)
            throws GeneralSecurityException;
}
