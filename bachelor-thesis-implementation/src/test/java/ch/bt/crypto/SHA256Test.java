package ch.bt.crypto;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;
import java.util.Random;

public class SHA256Test {

    @ParameterizedTest
    @ValueSource(ints = {128, 256, 512, 1024})
    public void testHash(final int securityParameter) {
        final SHA256Hash sha256Hash = new SHA256Hash();
        final byte[] plaintext = new byte[securityParameter];
        new Random().nextBytes(plaintext);
        assertFalse(Arrays.equals(sha256Hash.hash(plaintext), plaintext));
    }

    @Test
    public void testDeterminism() {
        final int securityParameter = 256;
        final SHA256Hash sha256Hash = new SHA256Hash();
        final SHA256Hash sha256Hash1 = new SHA256Hash();
        final byte[] plaintext = new byte[securityParameter];
        new Random().nextBytes(plaintext);
        assertTrue(Arrays.equals(sha256Hash.hash(plaintext), sha256Hash.hash(plaintext)));
        assertTrue(Arrays.equals(sha256Hash.hash(plaintext), sha256Hash1.hash(plaintext)));

    }
}
