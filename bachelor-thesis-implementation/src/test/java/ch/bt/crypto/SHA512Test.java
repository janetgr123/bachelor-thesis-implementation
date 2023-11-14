package ch.bt.crypto;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.util.Arrays;
import java.util.Random;

public class SHA512Test {
    @ParameterizedTest
    @ValueSource(ints = {128, 256, 512, 1024})
    public void testHash(final int securityParameter) {
        final SHA512Hash sha512Hash = new SHA512Hash();
        final byte[] plaintext = new byte[securityParameter];
        new Random().nextBytes(plaintext);
        assertFalse(Arrays.equals(sha512Hash.hash(plaintext), plaintext));
    }

    @Test
    public void testDeterminism() {
        final int securityParameter = 512;
        final SHA512Hash sha512Hash = new SHA512Hash();
        final SHA512Hash sha512Hash1 = new SHA512Hash();
        final byte[] plaintext = new byte[securityParameter];
        new Random().nextBytes(plaintext);
        assertArrayEquals(sha512Hash.hash(plaintext), sha512Hash.hash(plaintext));
        assertArrayEquals(sha512Hash.hash(plaintext), sha512Hash1.hash(plaintext));
    }
}
