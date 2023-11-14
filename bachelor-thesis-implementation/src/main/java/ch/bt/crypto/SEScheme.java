package ch.bt.crypto;

import ch.bt.model.Pair;

public interface SEScheme {

    SecretKey generateKey(final int securityParameter);

    byte[] encrypt(final byte[] input);

    byte[] decrypt(final byte[] input);

    Pair encrypt(final Pair input);

    Pair decrypt(final Pair input);
}
