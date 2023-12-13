package ch.bt.emm;

import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.multimap.Ciphertext;
import ch.bt.model.multimap.Label;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.multimap.Plaintext;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Set;
import java.util.Map;

public interface EMM {
    List<SecretKey> setup(final int securityParameter) throws GeneralSecurityException, IOException;

    EncryptedIndex buildIndex(final Map<Label, Set<Plaintext>> multiMap)
            throws GeneralSecurityException, IOException;

    SearchToken trapdoor(final Label searchLabel) throws GeneralSecurityException, IOException;

    Set<Ciphertext> search(final SearchToken searchToken, final EncryptedIndex encryptedIndex)
            throws GeneralSecurityException, IOException;

    Set<Plaintext> result(final Set<Ciphertext> ciphertexts, final Label searchLabel) throws GeneralSecurityException;

    int getNumberOfDummyValues();
}
