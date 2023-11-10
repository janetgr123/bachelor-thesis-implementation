package ch.bt.crypto;

public interface KeyDerivator {

    public SecretKeySingle deriveKeyFrom(final SecretKeySingle masterKey, final byte[] salt);
}
