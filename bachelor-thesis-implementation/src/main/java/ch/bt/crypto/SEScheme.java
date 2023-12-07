package ch.bt.crypto;

import ch.bt.model.multimap.CiphertextWithIV;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

public interface SEScheme {

    SecretKey generateKey(final int securityParameter) throws GeneralSecurityException;

    CiphertextWithIV encrypt(final Plaintext input) throws GeneralSecurityException;

    Plaintext decrypt(final CiphertextWithIV ciphertextWithIV) throws GeneralSecurityException;

    CiphertextWithIV encryptLabel(final Label input) throws GeneralSecurityException;

    Label decryptLabel(final CiphertextWithIV ciphertextWithIV) throws GeneralSecurityException;
}
