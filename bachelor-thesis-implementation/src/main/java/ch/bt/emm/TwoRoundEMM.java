package ch.bt.emm;

import ch.bt.crypto.SEScheme;
import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.multimap.Ciphertext;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.searchtoken.SearchToken;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;

public interface TwoRoundEMM {
    List<SecretKey> setup(final int securityParameter) throws GeneralSecurityException, IOException;

    EncryptedIndex buildIndex(final Map<Label, Set<Plaintext>> multiMap)
            throws GeneralSecurityException, IOException;

    SearchToken trapdoor(final Label searchLabel) throws GeneralSecurityException, IOException;

    SearchToken trapdoor(final Label label, final Set<Ciphertext> ciphertexts)
            throws GeneralSecurityException, IOException;

    Set<Ciphertext> search(final SearchToken searchToken, final EncryptedIndex encryptedIndex)
            throws GeneralSecurityException, IOException;

    int getNumberOfDummyValues();

    int getNumberOfDummyCT();

    Set<Ciphertext> search2(final SearchToken searchToken, final EncryptedIndex encryptedIndex)
            throws IOException;

    Set<Plaintext> result(final Set<Ciphertext> ciphertexts, final Label searchLabel)
            throws GeneralSecurityException;

    SEScheme getSeScheme();
}
