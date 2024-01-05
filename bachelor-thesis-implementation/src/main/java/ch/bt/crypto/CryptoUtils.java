package ch.bt.crypto;

import ch.bt.model.multimap.CiphertextWithIV;

import org.bouncycastle.util.Strings;

import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

/**
 * This class is a collection of method wrappers of crypto primitives of the <a
 * href="https://github.com/indrabasak/bouncycastle-fips-examples/blob/master/doc/BCFipsIn100.pdf">Bouncy
 * Castle FIPS API</a> date accessed: 21.11.2023
 *
 * @author Janet Greutmann
 */
public class CryptoUtils {

    /**
     * Generating an AES Key
     *
     * @param securityParameter the size of the key in bits
     * @return a symmetric AES encryption key of length securityParameter bits
     * @throws GeneralSecurityException
     */
    public static SecretKey generateKeyForAES(final int securityParameter)
            throws GeneralSecurityException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BCFIPS");
        keyGenerator.init(securityParameter);
        return keyGenerator.generateKey();
    }

    /**
     * AES CBC Block Cipher with PKCS7 Padding
     *
     * @param key symmetric AES encryption key
     * @param plaintext input plaintext to encrypt with the AES scheme
     * @return Enc(key, plaintext) ciphertext and used iv, wrapped into a class
     * @throws GeneralSecurityException
     */
    public static CiphertextWithIV cbcEncrypt(final SecretKey key, final byte[] plaintext)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BCFIPS");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return new CiphertextWithIV(cipher.getIV(), cipher.doFinal(plaintext));
    }

    /**
     * @param key for AES
     * @param ciphertextWithIV the ciphertext and the iv used in the encryption process
     * @return Dec(key, ciphertext, iv)
     * @throws GeneralSecurityException
     */
    public static byte[] cbcDecrypt(final SecretKey key, final CiphertextWithIV ciphertextWithIV)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BCFIPS");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ciphertextWithIV.iv()));
        return cipher.doFinal(ciphertextWithIV.data());
    }

    /**
     * Hashing with SHA3-512
     *
     * @param data the byte array to hash
     * @return SHA3-512 hash of the data
     * @throws GeneralSecurityException
     */
    public static byte[] calculateSha3Digest(final byte[] data) throws GeneralSecurityException {
        MessageDigest hash = MessageDigest.getInstance("SHA3-512", "BCFIPS");
        return hash.digest(data);
    }

    /**
     * Hashing with SHA3-512
     *
     * @param data the string to hash
     * @return hash of the data
     * @throws GeneralSecurityException
     */
    public static byte[] calculateSha3Digest(final String data) throws GeneralSecurityException {
        MessageDigest hash = MessageDigest.getInstance("SHA3-512", "BCFIPS");
        return hash.digest(Strings.toByteArray(data));
    }

    /**
     * Key Generation with HMac
     *
     * @param securityParameter the length in bits of the key
     * @return secret key of length securityParameter bits, generated using the HmacSHA512 algorithm
     * @throws GeneralSecurityException
     */
    public static SecretKey generateKeyWithHMac(final int securityParameter)
            throws GeneralSecurityException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA512", "BCFIPS");
        keyGenerator.init(securityParameter);
        return keyGenerator.generateKey();
    }

    /**
     * Hashing with HMac SHA512
     *
     * @param key the secret key for hashing
     * @param data the byte array to hash
     * @return HmacSHA512 hash of the data
     * @throws GeneralSecurityException
     */
    public static byte[] calculateHmac(final SecretKey key, final byte[] data)
            throws GeneralSecurityException {
        Mac hmac = Mac.getInstance("HMacSHA512", "BCFIPS");
        hmac.init(key);
        return hmac.doFinal(data); // fulfills the role of the digest() method
    }
}
