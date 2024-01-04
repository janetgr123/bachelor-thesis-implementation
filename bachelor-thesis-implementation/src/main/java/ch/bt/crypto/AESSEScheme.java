package ch.bt.crypto;

import ch.bt.model.multimap.CiphertextWithIV;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

/**
 * This class is a wrapper for an AES encryption scheme. The underlined crypto primitives are
 * implemented using the <a
 * href="https://github.com/indrabasak/bouncycastle-fips-examples/blob/master/doc/BCFipsIn100.pdf">Bouncy
 * Castle FIPS API</a> date accessed: 21.11.2023
 *
 * @author Janet Greutmann
 */
public class AESSEScheme implements SEScheme {

    /** symmetric encryption key of the scheme */
    private final SecretKey key;

    public AESSEScheme(final int securityParameter) throws GeneralSecurityException {
        this.key = generateKey(securityParameter);
    }

    public AESSEScheme(final SecretKey key) {
        this.key = key;
    }

    /**
     * @param securityParameter the length of the key in bits
     * @return a symmetric AES encryption key of length securityParameter
     */
    @Override
    public SecretKey generateKey(final int securityParameter) throws GeneralSecurityException {
        return CryptoUtils.generateKeyForAES(securityParameter);
    }

    /**
     * @param input the plaintext input in byte array and wrapped into a class
     * @return Enc(key, input) in byte array and wrapped into a class
     * @throws GeneralSecurityException
     */
    @Override
    public CiphertextWithIV encrypt(final Plaintext input) throws GeneralSecurityException {
        return CryptoUtils.cbcEncrypt(key, input.data());
    }

    /**
     * @param ciphertextWithIV the ciphertext with the iv used in the encryption process, both as
     *     byte arrays and wrapped into a class
     * @return Dec(key, ciphertext, iv) in byte array and wrapped into a class
     * @throws GeneralSecurityException
     */
    @Override
    public Plaintext decrypt(final CiphertextWithIV ciphertextWithIV)
            throws GeneralSecurityException {
        return new Plaintext(CryptoUtils.cbcDecrypt(key, ciphertextWithIV));
    }

    /**
     * @param input a label as a byte array, wrapped into a class
     * @return Enc(key, input) in byte array and wrapped into a class
     * @throws GeneralSecurityException
     */
    @Override
    public CiphertextWithIV encryptLabel(final Label input) throws GeneralSecurityException {
        return CryptoUtils.cbcEncrypt(key, input.label());
    }

    /**
     * @param ciphertextWithIV the ciphertext with the iv used in the encryption process, both as
     *     byte arrays and wrapped into a class
     * @return Dec(key, ciphertext, iv) in byte array and wrapped into a label
     * @throws GeneralSecurityException
     */
    @Override
    public Label decryptLabel(final CiphertextWithIV ciphertextWithIV)
            throws GeneralSecurityException {
        return new Label(CryptoUtils.cbcDecrypt(key, ciphertextWithIV));
    }
}
