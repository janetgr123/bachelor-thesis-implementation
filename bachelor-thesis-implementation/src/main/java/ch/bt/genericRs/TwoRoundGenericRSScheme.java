package ch.bt.genericRs;

import ch.bt.emm.TwoRoundEMM;
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

/**
 * This interface specifies the algorithms of a 2-interactive range scheme.
 *
 * @author Janet Greutmann
 */
public interface TwoRoundGenericRSScheme {
    /**
     * @param securityParameter the length of the keys in bits
     * @return two secret keys, one for the PRF and one for the symmetric encryption scheme
     * @throws GeneralSecurityException
     * @throws IOException
     */
    List<SecretKey> setup(final int securityParameter) throws GeneralSecurityException, IOException;

    /**
     * @param multiMap the plaintext data stored in a multimap
     * @return the encrypted index of the vertices of the graph
     * @throws GeneralSecurityException
     */
    EncryptedIndex buildIndex(final Map<Label, Set<Plaintext>> multiMap)
            throws GeneralSecurityException, IOException;

    /**
     * @param q the range query
     * @return a list of search token in random order that enable access to the entries in the
     *     encrypted index that cover the range q.
     */
    List<SearchToken> trapdoor(final CustomRange q);

    /**
     * @param q the range query
     * @param ciphertexts the ciphertexts returned by search
     * @return a list of search token in random order that enable access to the entries in the
     *     encrypted index that cover the range q.
     */
    List<SearchToken> trapdoor(final CustomRange q, final Set<Ciphertext> ciphertexts)
            throws GeneralSecurityException, IOException;

    /**
     * @param searchToken a list of search token that has been generated with trapdoor
     * @param encryptedIndex the encrypted index
     * @return the set of ciphertexts in the counter tables that correspond to the range encrypted
     *     in the token
     */
    Set<Ciphertext> search(
            final List<SearchToken> searchToken, final EncryptedIndex encryptedIndex);

    /**
     * @param searchToken a list of search token that has been generated with trapdoor(range,
     *     ciphertexts)
     * @param encryptedIndex the encrypted index
     * @return the set of ciphertexts that correspond to the range encrypted in the token
     */
    Set<Ciphertext> search2(
            final List<SearchToken> searchToken, final EncryptedIndex encryptedIndex)
            throws IOException;

    /**
     * @param ciphertexts the set of ciphertexts that search2 found for a given token list
     * @param q the range query
     * @return the corresponding set of plaintexts
     */
    Set<Plaintext> result(final Set<Ciphertext> ciphertexts, final CustomRange q)
            throws GeneralSecurityException;

    /**
     * Getter for the EMM class
     *
     * @return the class of the EMM as a string
     */
    String getClassOfEMM();

    /**
     * Getter for the number of dummy entries in the encrypted index of the EMM
     *
     * @return the number of dummy values in the encrypted index of the EMM
     */
    int getIndexDummies();

    /**
     * Getter for the EMM instance
     *
     * @return the EMM scheme instance
     */
    TwoRoundEMM getEMM();

    int getResponsePadding();
}
