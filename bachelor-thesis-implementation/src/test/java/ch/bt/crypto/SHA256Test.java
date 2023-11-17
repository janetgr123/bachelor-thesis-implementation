package ch.bt.crypto;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

@Disabled
public class SHA256Test {

    @ParameterizedTest
    @ValueSource(ints = {128, 256, 512, 1024})
    public void testHash(final int securityParameter) {
        final SHA256Hash sha256Hash = new SHA256Hash();
        final byte[] plaintext = new byte[securityParameter / Byte.SIZE];
        new Random().nextBytes(plaintext);
        assertFalse(Arrays.equals(sha256Hash.hash(plaintext), plaintext));
    }

    // TODO: FIX SHA256 WRAPPER!!!!!!!!!
    @Test
    public void testDeterminism() {
        final int securityParameter = 256;
        final SHA256Hash sha256Hash = new SHA256Hash();
        final SHA256Hash sha256Hash1 = new SHA256Hash();
        final byte[] plaintext = new byte[securityParameter / Byte.SIZE];
        new Random().nextBytes(plaintext);
        assertArrayEquals(sha256Hash.hash(plaintext), sha256Hash.hash(plaintext));
        assertArrayEquals(sha256Hash.hash(plaintext), sha256Hash1.hash(plaintext));
    }

    @Test
    public void testPrefix() {
        final int securityParameter = 128;
        final SHA256Hash sha256Hash = new SHA256Hash();
        final byte[] prefix = new byte[securityParameter / Byte.SIZE];
        new Random().nextBytes(prefix);
        final int i = new Random().nextInt(2);
        final int j = new Random().nextInt(2);
        final var toHash =
                org.bouncycastle.util.Arrays.concatenate(
                        prefix,
                        BigInteger.valueOf(i).toByteArray(),
                        BigInteger.valueOf(j).toByteArray());
        final var tmp = sha256Hash.hash(toHash);
        final var tmp2 = sha256Hash.hash(prefix);
        assertFalse(Arrays.equals(sha256Hash.hash(toHash), sha256Hash.hash(prefix)));

        final var b1 = new byte[securityParameter / Byte.SIZE];
        new Random().nextBytes(b1);
        final var b2 = new byte[securityParameter / Byte.SIZE];
        new Random().nextBytes(b2);
        final var toHash2 = org.bouncycastle.util.Arrays.concatenate(prefix, b1, b2);
        assertFalse(Arrays.equals(sha256Hash.hash(toHash2), sha256Hash.hash(prefix)));
    }
}
