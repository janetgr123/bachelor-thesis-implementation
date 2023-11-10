package ch.bt.emm;

import ch.bt.crypto.SecretKey;
import ch.bt.model.*;

import java.util.Map;
import java.util.Set;

public interface EMM {
    public SecretKey setup(final int securityParameter);

    public Map<EncryptedLabel, EncryptedValue> buildIndex(final Map<PlaintextLabel, Set<PlaintextValue>> multiMap);

    public SearchToken trapdoor(final Label label);

    public Set<Value> search(final SearchToken searchToken, final Map<EncryptedLabel, EncryptedValue> encryptedIndex);

    public Set<Value> result(final Set<Value> values);
}
