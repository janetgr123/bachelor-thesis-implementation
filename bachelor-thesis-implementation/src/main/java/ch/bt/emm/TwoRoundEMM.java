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

/** This interface specifies the algorithms of a 2-interactive EMM scheme. */
public interface TwoRoundEMM {
    /**
     * @param securityParameter the length of the keys in bits
     * @return two secret keys, one for the PRF and one for the symmetric encryption scheme
     * @throws GeneralSecurityException
     * @throws IOException
     */
    List<SecretKey> setup(final int securityParameter) throws GeneralSecurityException, IOException;

    /**
     * @param multiMap the plaintext data stored in a multimap
     * @return the encrypted index of the multimap according to the scheme
     * @throws GeneralSecurityException
     * @throws IOException
     */
    EncryptedIndex buildIndex(final Map<Label, Set<Plaintext>> multiMap)
            throws GeneralSecurityException, IOException;

    /**
     * @param searchLabel the search label in plaintext
     * @return a search token that enables access to the entries in the encrypted index counter
     *     tables that correspond to the search label.
     * @throws GeneralSecurityException
     * @throws IOException
     */
    SearchToken trapdoor(final Label searchLabel) throws GeneralSecurityException, IOException;

    /**
     * @param label the search label in plaintext
     * @param ciphertexts the ciphertexts of the counter table returned by search
     * @return a search token that enables access to the entry in the encrypted index that
     *     corresponds to the search label.
     * @throws GeneralSecurityException
     * @throws IOException
     */
    SearchToken trapdoor(final Label label, final Set<Ciphertext> ciphertexts)
            throws GeneralSecurityException, IOException;

    /**
     * @param searchToken the search token that has been generated with trapdoor
     * @param encryptedIndex the encrypted index of the counter tables
     * @return the set of ciphertexts in the counter tables that correspond to the label encrypted
     *     in the token
     * @throws GeneralSecurityException
     * @throws IOException
     */
    Set<Ciphertext> search(final SearchToken searchToken, final EncryptedIndex encryptedIndex)
            throws GeneralSecurityException, IOException;

    /**
     * @param searchToken the search token that has been generated with trapdoor(label, ciphertexts)
     * @param encryptedIndex the encrypted index of the value tables
     * @return the set of ciphertexts that correspond to the label encrypted in the token
     * @throws IOException
     */
    Set<Ciphertext> search2(final SearchToken searchToken, final EncryptedIndex encryptedIndex)
            throws IOException;

    /**
     * @param ciphertexts the set of ciphertexts that search2 found for a given token
     * @param searchLabel the search label in plaintext
     * @return the set of plaintexts that have been encrypted to those ciphertexts using the given
     *     ivs and the schemeKey
     * @throws GeneralSecurityException
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
     * Getter for the number of dummy entries in the encrypted index
     *
     * @return the number of dummy values in the counter tables
     */
    int getNumberOfDummyCT();

    /**
     * Getter for the encryption scheme
     *
     * @return the encryption scheme instance
     */
    SEScheme getSeScheme();
}
