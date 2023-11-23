package ch.bt.crypto;

import org.apache.commons.compress.utils.BitInputStream;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.ByteOrder;
import java.util.Arrays;

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
        return s.getBytes();
    }

    public static BitInputStream fromByteArrayToBitInputStream(final byte[] array) {
        return new BitInputStream(new ByteArrayInputStream(array), ByteOrder.BIG_ENDIAN);
    }
}
