package ch.bt.crypto;

public interface KeyDerivator {

    SecretKeySingle deriveKeyFrom(final SecretKeySingle masterKey, final byte[] salt);
}
