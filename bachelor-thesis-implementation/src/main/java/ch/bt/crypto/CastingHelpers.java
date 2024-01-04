package ch.bt.crypto;

import ch.bt.model.multimap.Label;
import ch.bt.model.rc.CustomRange;

import org.apache.commons.compress.utils.BitInputStream;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.function.Predicate;

/**
 * This class is a collection of methods that transform types, e.g., from byte array to int.
 *
 * @author Janet Greutmann
 */
public class CastingHelpers {

    /**
     * @param array the byte array
     * @return the integer that is represented by the byte array
     */
    public static int fromByteArrayToInt(final byte[] array) {
        return new BigInteger(array).intValue();
    }

    /**
     * @param array the byte array
     * @param n the modulus for hashing
     * @return the integer that is represented by the byte array mod n
     */
    public static int fromByteArrayToHashModN(final byte[] array, final int n) {
        return Math.floorMod(fromByteArrayToInt(array), n);
    }

    /**
     * @param i the integer
     * @return the byte representation of i as an array
     */
    public static byte[] fromIntToByteArray(final int i) {
        return BigInteger.valueOf(i).toByteArray();
    }

    /**
     * @param s the string s
     * @return the byte representation of the string as array
     */
    public static byte[] fromStringToByteArray(final String s) {
        final var n = s.length();
        final var bytes =
                Arrays.stream(s.substring(1, n - 1).split(","))
                        .map(el -> el.replaceAll(" ", ""))
                        .filter(Predicate.not(String::isEmpty))
                        .map(Byte::parseByte)
                        .toArray(Byte[]::new);
        final var result = new byte[bytes.length];
        int i = 0;
        for (final var b : bytes) {
            result[i] = b;
            i++;
        }
        return result;
    }

    /**
     * @param array the byte array
     * @return a bit input stream in big endian of the byte array
     */
    public static BitInputStream fromByteArrayToBitInputStream(final byte[] array) {
        return new BitInputStream(new ByteArrayInputStream(array), ByteOrder.BIG_ENDIAN);
    }

    /**
     * @param range the integer range with id, start and end point
     * @return a label that contains a byte array that is the concatenation of the byte
     *     representations of the interval borders.
     */
    public static Label toLabel(final CustomRange range) {
        return new Label(
                org.bouncycastle.util.Arrays.concatenate(
                        CastingHelpers.fromIntToByteArray(range.getMinimum()),
                        CastingHelpers.fromIntToByteArray(range.getMaximum())));
    }
}
