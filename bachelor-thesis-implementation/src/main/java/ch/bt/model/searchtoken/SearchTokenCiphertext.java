package ch.bt.model.searchtoken;

import ch.bt.model.CiphertextWithIV;

public record SearchTokenCiphertext(CiphertextWithIV token) implements SearchToken {
}
