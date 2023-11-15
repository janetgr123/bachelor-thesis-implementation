package ch.bt.emm;

import ch.bt.crypto.SecretKey;
import ch.bt.model.*;

import java.util.Set;

public interface EMM {
    SecretKey setup(final int securityParameter);

    EncryptedIndex buildIndex();

    SearchToken trapdoor(final Label label);

    Set<PairLabelValue> search(final SearchToken searchToken, final EncryptedIndex encryptedIndex);

    Set<Value> result(final Set<PairLabelValue> values, final Label label);
}
