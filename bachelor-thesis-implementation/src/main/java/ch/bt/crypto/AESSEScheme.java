package ch.bt.crypto;

import ch.bt.model.*;
import ch.bt.model.Plaintext;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

public class AESSEScheme implements SEScheme {

    private final SecretKey key;

    public AESSEScheme(final int securityParameter) throws GeneralSecurityException {
        this.key = generateKey(securityParameter);
    }

    public AESSEScheme(final SecretKey key) {
        this.key = key;
    }

    @Override
    public SecretKey generateKey(final int securityParameter) throws GeneralSecurityException {
        return CryptoUtils.generateKeyForAES(securityParameter);
    }

    @Override
    public CiphertextWithIV encrypt(final Plaintext input) throws GeneralSecurityException {
        return CryptoUtils.cbcEncrypt(key, input.data());
    }

    @Override
    public Plaintext decrypt(final CiphertextWithIV ciphertextWithIV)
            throws GeneralSecurityException {
        return new Plaintext(CryptoUtils.cbcDecrypt(key, ciphertextWithIV));
    }

    @Override
    public CiphertextWithIV encryptLabel(final Label input) throws GeneralSecurityException {
        return CryptoUtils.cbcEncrypt(key, input.label());
    }

    @Override
    public Label decryptLabel(final CiphertextWithIV ciphertextWithIV)
            throws GeneralSecurityException {
        return new Label(CryptoUtils.cbcDecrypt(key, ciphertextWithIV));
    }
}
