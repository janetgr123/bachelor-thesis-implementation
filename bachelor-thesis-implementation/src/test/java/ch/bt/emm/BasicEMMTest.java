package ch.bt.emm;

import ch.bt.model.PlaintextLabel;
import ch.bt.model.PlaintextValue;
import ch.bt.model.Value;
import org.junit.Assert;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.*;

public class BasicEMMTest {

    @Test
    public void testCorrectness() {
        final int securityParameter = 512;
        BasicEMM basicEMM = new BasicEMM(new SecureRandom(), securityParameter);
        final Map<PlaintextLabel, Set<PlaintextValue>> multimap = new HashMap<>();
        PlaintextLabel searchLabel = null;
        Random random = new Random();
        int index = (int) (100 * Math.random());
        while (multimap.size() < 100) {
            final var values = new HashSet<PlaintextValue>();
            int size = (int) (10 * Math.random());
            while (values.size() < size) {
                byte[] v = new byte[securityParameter / 2];
                random.nextBytes(v);
                values.add(new PlaintextValue(v));
            }
            byte[] l = new byte[securityParameter / 2];
            random.nextBytes(l);
            final var label = new PlaintextLabel(l);
            if (multimap.size() == index) {
                searchLabel = label;
            }
            multimap.put(label, values);
        }
        final var encryptedIndex = basicEMM.buildIndex(multimap);
        final var searchToken = basicEMM.trapdoor(searchLabel);
        final var ciphertexts = basicEMM.search(searchToken, encryptedIndex);
        final var values = basicEMM.result(ciphertexts);
        final var expectedValues = multimap.get(searchLabel);
        Assert.assertEquals(expectedValues.size(), values.size());
        for (Value value : values) {
            Assert.assertEquals(1, expectedValues.stream().filter(el -> Arrays.equals(el.getValue(), value.getValue())).toList().size());
        }
    }
}
