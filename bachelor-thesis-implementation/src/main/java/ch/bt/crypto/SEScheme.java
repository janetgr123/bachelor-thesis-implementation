package ch.bt.crypto;

public interface SEScheme {

    SecretKey generateKey(final int securityParameter);

    byte[] encrypt(final byte[] input);

    byte[] decrypt(final byte[] input);

}
