package ch.bt.crypto;

import ch.bt.model.multimap.Label;

import org.apache.commons.compress.utils.BitInputStream;
import org.bouncycastle.crypto.OutputXOFCalculator;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsXOFOperatorFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

import javax.crypto.SecretKey;

/**
 * <a
 * href="https://github.com/indrabasak/bouncycastle-fips-examples/blob/master/doc/BCFipsIn100.pdf">...</a>
 * date accessed: 21.11.2023
 */
public class DPRF {

    /**
     * Use Expandable Output Function
     *
     * @param data
     * @param left indicates if left (0) or right (1) half should be returned
     * @return left or right half of data expanded by factor 2
     */
    public static byte[] expandData(final byte[] data, final long left) throws IOException {
        final int length = data.length * 2;
        FipsXOFOperatorFactory<FipsSHS.Parameters> factory =
                new FipsSHS.XOFOperatorFactory<>();
        OutputXOFCalculator<FipsSHS.Parameters> calculator =
                factory.createOutputXOFCalculator(FipsSHS.SHAKE256);
        OutputStream digestStream = calculator.getFunctionStream();
        digestStream.write(data);
        digestStream.close();
        final var output = calculator.getFunctionOutput(length);
        final var n = output.length;
        return left == 0
                ? Arrays.copyOfRange(output, 0, n / 2)
                : Arrays.copyOfRange(output, n / 2, n);
    }

    public static byte[] calculateFk(
            final BitInputStream bits, final int numberOfBits, final byte[] key)
            throws IOException {
        final var availableNumberOfBits = bits.bitsAvailable();
        if (availableNumberOfBits > numberOfBits) {
            bits.readBits((int) (availableNumberOfBits - numberOfBits));
        }
        byte[] result = null;
        for (int i = 0; i < numberOfBits; i++) {
            final var bit = bits.readBits(1);
            if (i == 0) {
                result = expandData(key, bit);
            } else {
                result = expandData(result, bit);
            }
        }
        return result;
    }

    public static byte[] calculateFk(final BitInputStream bits, final byte[] key)
            throws IOException {
        final var numberOfBits = bits.bitsAvailable();
        byte[] result = null;
        for (int i = 0; i < numberOfBits; i++) {
            final var bit = bits.readBits(1);
            if (i == 0) {
                result = expandData(key, bit);
            } else {
                result = expandData(result, bit);
            }
        }
        return result;
    }

    public static byte[] generateToken(final SecretKey key, final Label label) throws IOException {
        return DPRF.calculateFk(
                CastingHelpers.fromByteArrayToBitInputStream(label.label()), key.getEncoded());
    }

    public static byte[] evaluateDPRF(final byte[] token, final int i, final int tableNo)
            throws IOException {
        final var input =
                org.bouncycastle.util.Arrays.concatenate(
                        CastingHelpers.fromIntToByteArray(i),
                        CastingHelpers.fromIntToByteArray(tableNo));
        return calculateFk(CastingHelpers.fromByteArrayToBitInputStream(input), token);
    }
}
