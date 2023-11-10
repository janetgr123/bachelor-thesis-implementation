package ch.bt.emm;

import ch.bt.crypto.SecretKey;
import ch.bt.model.*;

import java.util.Map;
import java.util.Set;

public interface EMM {
    SecretKey setup(final int securityParameter);

    Map<EncryptedLabel, EncryptedValue> buildIndex(final Map<PlaintextLabel, Set<PlaintextValue>> multiMap);

    SearchToken trapdoor(final Label label);

    Set<Value> search(final SearchToken searchToken, final Map<EncryptedLabel, EncryptedValue> encryptedIndex);

    Set<Value> result(final Set<Value> values);
}
