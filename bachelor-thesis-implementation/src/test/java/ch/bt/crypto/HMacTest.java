package ch.bt.crypto;

import org.bouncycastle.crypto.params.KeyParameter;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

public class HMacTest {
    @Test
    public void testHash() {
        final int securityParameter = 512;
        final KeyGenerator keyGenerator = new KeyGenerator(new SecureRandom(), securityParameter);
        final SecretKey key = keyGenerator.generateKey();
        if (key instanceof SecretKeySingle) {
            final HMacHash hMac = new HMacHash(new KeyParameter(key.getKey().keys().get(0).getBytes()));
            final byte[] plaintext = new byte[securityParameter];
            new Random().nextBytes(plaintext);
            assertFalse(Arrays.equals(hMac.hash(plaintext), plaintext));
        }
    }

    @Test
    public void testDeterminism() {
        final int securityParameter = 512;
        final KeyGenerator keyGenerator = new KeyGenerator(new SecureRandom(), securityParameter);
        final SecretKey key = keyGenerator.generateKey();
        if (key instanceof SecretKeySingle) {
            final HMacHash hMac = new HMacHash(new KeyParameter(key.getKey().keys().get(0).getBytes()));
            final HMacHash hMac2 = new HMacHash(new KeyParameter(key.getKey().keys().get(0).getBytes()));
            final byte[] plaintext = new byte[securityParameter];
            new Random().nextBytes(plaintext);
            assertFalse(Arrays.equals(hMac.hash(plaintext), plaintext));
            assertTrue(Arrays.equals(hMac.hash(plaintext), hMac.hash(plaintext)));
            assertTrue(Arrays.equals(hMac.hash(plaintext), hMac2.hash(plaintext)));
        }
    }

    @Test
    public void testKeyDependency() {
        final int securityParameter = 512;
        final KeyGenerator keyGenerator = new KeyGenerator(new SecureRandom(), securityParameter);
        final SecretKey key = keyGenerator.generateKey();
        final SecretKey key2 = keyGenerator.generateKey();
        if (key instanceof SecretKeySingle && key2 instanceof SecretKeySingle) {
            final HMacHash hMac = new HMacHash(new KeyParameter(key.getKey().keys().get(0).getBytes()));
            final HMacHash hMac2 = new HMacHash(new KeyParameter(key2.getKey().keys().get(0).getBytes()));
            final byte[] plaintext = new byte[securityParameter];
            new Random().nextBytes(plaintext);
            assertFalse(Arrays.equals(hMac.hash(plaintext), hMac2.hash(plaintext)));
        }
    }
}
