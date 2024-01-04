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

/** This interface specifies the algorithms of a 1-interactive EMM scheme. */
public interface EMM {
    /**
     * @param securityParameter the length of the keys in bits
     * @return two secret keys, one for the PRF and one for the symmetric encryption scheme
     * @throws GeneralSecurityException
     */
    List<SecretKey> setup(final int securityParameter) throws GeneralSecurityException, IOException;

    /**
     * @param multiMap the plaintext data stored in a multimap
     * @return the encrypted index of the multimap according to the scheme
     * @throws GeneralSecurityException
     */
    EncryptedIndex buildIndex(final Map<Label, Set<Plaintext>> multiMap)
            throws GeneralSecurityException, IOException;

    /**
     * @param searchLabel the search label in plaintext
     * @return a search token that enables access to the entries in the encrypted index that
     *     correspond to the search label.
     * @throws GeneralSecurityException
     */
    SearchToken trapdoor(final Label searchLabel) throws GeneralSecurityException, IOException;

    /**
     * @param searchToken the search token that has been generated with trapdoor
     * @param encryptedIndex the encrypted index
     * @return the set of ciphertexts that correspond to the label encrypted in the token
     * @throws GeneralSecurityException
     */
    Set<Ciphertext> search(final SearchToken searchToken, final EncryptedIndex encryptedIndex)
            throws GeneralSecurityException, IOException;

    /**
     * @param ciphertexts the set of ciphertexts that search2 found for a given token
     * @param searchLabel the search label in plaintext
     * @return the set of plaintexts that have been encrypted to those ciphertexts using the given
     *     ivs and the schemeKey
     */
    Set<Plaintext> result(final Set<Ciphertext> ciphertexts, final Label searchLabel)
            throws GeneralSecurityException;

    /**
     * Getter for the number of dummy entries in the encrypted index
     *
     * @return the number of dummy values in the value tables
     */
    int getNumberOfDummyValues();

    /**
     * Getter for the PRF key (because of inheritence)
     *
     * @return the PRF key
     */
    SecretKey getPrfKey();

    /**
     * Getter for the encryption scheme
     *
     * @return the encryption scheme instance
     */
    SEScheme getSeScheme();
}
