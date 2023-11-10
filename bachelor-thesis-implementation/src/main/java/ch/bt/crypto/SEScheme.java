package ch.bt.crypto;

public interface SEScheme {

    public SecretKey generateKey(final int securityParameter);

    public byte[] encrypt(final byte[] input);

    public byte[] decrypt(final byte[] input);

}
