package ch.bt.crypto;

import ch.bt.model.CiphertextWithIV;

import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.OutputXOFCalculator;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsXOFOperatorFactory;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.bouncycastle.util.Strings;

import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * <a
 * href="https://github.com/indrabasak/bouncycastle-fips-examples/blob/master/doc/BCFipsIn100.pdf">...</a>
 */
public class CryptoUtils {

    private static final byte[] PERSONALISATION_STRING = Strings.toByteArray("I LOVE CRYPTO");
    private static final byte[] NONCE =
            Strings.toByteArray("This is a number that is only used once.");

    /**
     * @param securityParameter that refers to the number of bits
     * @return SecureRandom for keys based on SHA512 HMAC
     */
    public static SecureRandom buildDRBGForKeys(final int securityParameter) {
        EntropySourceProvider entSource = new BasicEntropySourceProvider(new SecureRandom(), true);
        FipsDRBG.Builder dRBGBuilder =
                FipsDRBG.SHA512_HMAC
                        .fromEntropySource(entSource)
                        .setSecurityStrength(securityParameter)
                        .setEntropyBitsRequired(securityParameter)
                        .setPersonalizationString(PERSONALISATION_STRING);
        return dRBGBuilder.build(NONCE, true); // prediction resistant
    }

    /**
     * Generating an AES Key
     *
     * @param securityParameter refers to the size of the key in bits
     * @return SecretKey for AES
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
     * @param key for AES
     * @param plaintext to encrypt
     * @return iv and the encrypted data
     */
    public static CiphertextWithIV cbcEncrypt(final SecretKey key, final byte[] plaintext)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BCFIPS");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return new CiphertextWithIV(cipher.getIV(), cipher.doFinal(plaintext));
    }

    /**
     * @param key for AES
     * @param ciphertextWithIV contains iv and encrypted data
     * @return plaintext that has been encrypted with AES using key and iv
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
     * @param data to hash
     * @return hash of the data
     */
    public static byte[] calculateSha3Digest(final byte[] data) throws GeneralSecurityException {
        MessageDigest hash = MessageDigest.getInstance("SHA3-512", "BCFIPS");
        return hash.digest(data);
    }

    /**
     * Hashing with SHA3-512
     *
     * @param data to hash
     * @return hash of the data
     */
    public static byte[] calculateSha3Digest(final String data) throws GeneralSecurityException {
        MessageDigest hash = MessageDigest.getInstance("SHA3-512", "BCFIPS");
        return hash.digest(Strings.toByteArray(data));
    }

    /**
     * Use Expandable Output Function as KDF
     *
     * @param masterKey
     * @param securityParameter length in bits of the derived keys
     * @return derived key of the masterkey of length securityParameter bits
     */
    public static SecretKey deriveKey(final SecretKey masterKey, final int securityParameter)
            throws IOException,
                    NoSuchAlgorithmException,
                    NoSuchProviderException,
                    InvalidKeySpecException {
        FipsXOFOperatorFactory<FipsSHS.Parameters> factory =
                new FipsSHS.XOFOperatorFactory<FipsSHS.Parameters>();
        OutputXOFCalculator<FipsSHS.Parameters> calculator =
                factory.createOutputXOFCalculator(FipsSHS.SHAKE256);
        OutputStream digestStream = calculator.getFunctionStream();
        digestStream.write(masterKey.getEncoded());
        digestStream.close();
        final var keyFactory = SecretKeyFactory.getInstance("HmacSHA512", "BCFIPS");
        return keyFactory.generateSecret(
                new SecretKeySpec(
                        calculator.getFunctionOutput(
                                securityParameter / Byte.SIZE), // here we need bytes
                        "HmacSHA512"));
    }

    /**
     * Key Generation with HMac
     *
     * @param securityParameter length in bits of the key
     * @return SecretKey of length securityParameter bits
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
     * @param key for HMac SHA512 hashing
     * @param data to hash
     * @return hash of the data
     * @throws GeneralSecurityException
     */
    public static byte[] calculateHmac(final SecretKey key, final byte[] data)
            throws GeneralSecurityException {
        Mac hmac = Mac.getInstance("HMacSHA512", "BCFIPS");
        hmac.init(key);
        return hmac.doFinal(data); // fulfills the role of the digest() method
    }
}
