package ch.bt.crypto;

import static org.junit.jupiter.api.Assertions.*;

import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Stream;

public class HMacTest {
    private final static List<Integer> SECURITY_PARAMETERS = List.of(128, 256, 512, 1024);
    private final static Map<Integer, SecretKey> keys = new HashMap<>();
    private final static Map<Integer, byte[]> plaintexts = new HashMap<>();
    private final static Map<Integer, HMacHash> hMacs = new HashMap<>();

    @BeforeAll
    public static void init() {
        SECURITY_PARAMETERS.forEach(securityParameter -> {
                    final KeyGenerator keyGenerator = new KeyGenerator(new SecureRandom(), securityParameter);
                    final var key = keyGenerator.generateKey();
                    keys.put(securityParameter, key);
                    final var plaintext = new byte[securityParameter];
                    new Random().nextBytes(plaintext);
                    plaintexts.put(securityParameter, plaintext);
                    final var hMac = new HMacHash(new KeyParameter(key.getKey().keys().get(0).getBytes()));
                    hMacs.put(securityParameter, hMac);
                }
        );

    }

    private static Stream<Integer> getSecurityParameters() {
        return SECURITY_PARAMETERS.stream();
    }

    @ParameterizedTest
    @MethodSource("getSecurityParameters")
    public void testHash(final int securityParameter) {
        final var plaintext = plaintexts.get(securityParameter);
        final var hMac = hMacs.get(securityParameter);
        assertFalse(Arrays.equals(hMac.hash(plaintext), plaintext));
    }

    @ParameterizedTest
    @MethodSource("getSecurityParameters")
    public void testDeterminism(final int securityParameter) {
        final var key = keys.get(securityParameter);
        final var plaintext = plaintexts.get(securityParameter);
        final var hMac = hMacs.get(securityParameter);
        final HMacHash hMac2 = new HMacHash(new KeyParameter(key.getKey().keys().get(0).getBytes()));
        assertFalse(Arrays.equals(hMac.hash(plaintext), plaintext));
        assertArrayEquals(hMac.hash(plaintext), hMac.hash(plaintext));
        assertArrayEquals(hMac.hash(plaintext), hMac2.hash(plaintext));
    }

    @ParameterizedTest
    @MethodSource("getSecurityParameters")
    public void testKeyDependency(final int securityParameter) {
        final var plaintext = plaintexts.get(securityParameter);
        final var hMac = hMacs.get(securityParameter);
        final KeyGenerator keyGenerator = new KeyGenerator(new SecureRandom(), securityParameter);
        final SecretKey key2 = keyGenerator.generateKey();
        final HMacHash hMac2 = new HMacHash(new KeyParameter(key2.getKey().keys().get(0).getBytes()));
        assertFalse(Arrays.equals(hMac.hash(plaintext), hMac2.hash(plaintext)));
    }
}
