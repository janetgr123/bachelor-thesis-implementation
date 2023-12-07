package ch.bt.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import ch.bt.TestConfigurations;
import ch.bt.model.multimap.Label;

import org.apache.commons.compress.utils.BitInputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.util.Random;

/** Paper from Kiayias et al. */
@ExtendWith({TestConfigurations.class})
public class DPRFTest {

    @Test
    public void testDPRF() throws GeneralSecurityException, IOException {
        final int n = 4;
        final var bits =
                new BitInputStream(new ByteArrayInputStream(new byte[] {2}), ByteOrder.BIG_ENDIAN);
        final var key = CryptoUtils.generateKeyWithHMac(256);
        final var result = DPRF.calculateFk(bits, n, key.getEncoded());
        final var expectedResult =
                DPRF.expandData(
                        DPRF.expandData(
                                DPRF.expandData(DPRF.expandData(key.getEncoded(), 0), 0), 1),
                        0);

        // PROPERTY:    Delegatable PRF is deterministic
        assertArrayEquals(expectedResult, result);
    }

    @Test
    public void generateToken() throws IOException, GeneralSecurityException {
        final var key = CryptoUtils.generateKeyWithHMac(256);
        final var random = new Random();
        final var bytes = new byte[256 / Byte.SIZE];
        random.nextBytes(bytes);
        final var label = new Label(bytes);
        final var token = DPRF.generateToken(key, label);
        final var prfT0 = DPRF.evaluateDPRF(token, 0, 0);
        final var prfT1 = DPRF.evaluateDPRF(token, 0, 1);
        final var bytesT0 =
                org.bouncycastle.util.Arrays.concatenate(
                        bytes, BigInteger.ZERO.toByteArray(), BigInteger.ZERO.toByteArray());
        final var bytesT1 =
                org.bouncycastle.util.Arrays.concatenate(
                        bytes, BigInteger.ZERO.toByteArray(), BigInteger.ONE.toByteArray());
        final var expectedPrfT0 =
                DPRF.calculateFk(
                        CastingHelpers.fromByteArrayToBitInputStream(bytesT0), key.getEncoded());
        final var expectedPrfT1 =
                DPRF.calculateFk(
                        CastingHelpers.fromByteArrayToBitInputStream(bytesT1), key.getEncoded());

        // PROPERTY:    dPRF for input token, i, tableNo evaluates to fk(label, i, tableNo)
        assertArrayEquals(expectedPrfT0, prfT0);
        assertArrayEquals(expectedPrfT1, prfT1);
    }
}
