package ch.bt.crypto;

import ch.bt.model.multimap.Label;
import ch.bt.model.rc.CustomRange;

import org.apache.commons.compress.utils.BitInputStream;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.function.Predicate;

public class CastingHelpers {

    public static int fromByteArrayToInt(final byte[] array) {
        return new BigInteger(array).intValue();
    }

    public static int fromByteArrayToHashModN(final byte[] array, final int n) {
        return Math.floorMod(fromByteArrayToInt(array), n);
    }

    public static byte[] fromIntToByteArray(final int i) {
        return BigInteger.valueOf(i).toByteArray();
    }

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

    public static BitInputStream fromByteArrayToBitInputStream(final byte[] array) {
        return new BitInputStream(new ByteArrayInputStream(array), ByteOrder.BIG_ENDIAN);
    }

    public static Label toLabel(final CustomRange range) {
        return new Label(
                org.bouncycastle.util.Arrays.concatenate(
                        CastingHelpers.fromIntToByteArray(range.getMinimum()),
                        CastingHelpers.fromIntToByteArray(range.getMaximum())));
    }
}
