package ch.bt.crypto;

import ch.bt.model.PairLabelValue;

public interface SEScheme {

    SecretKey generateKey(final int securityParameter);

    byte[] encrypt(final byte[] input);

    byte[] decrypt(final byte[] input);

    PairLabelValue encrypt(final PairLabelValue input);

    PairLabelValue decrypt(final PairLabelValue input);
}
