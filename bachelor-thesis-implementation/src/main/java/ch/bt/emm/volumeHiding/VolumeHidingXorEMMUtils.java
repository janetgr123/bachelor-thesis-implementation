package ch.bt.emm.volumeHiding;

import ch.bt.crypto.CastingHelpers;
import ch.bt.crypto.DPRF;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.PairLabelPlaintext;
import ch.bt.model.multimap.PairNumber;
import ch.bt.model.multimap.Plaintext;

import java.io.IOException;
import java.util.*;

import javax.crypto.SecretKey;

public class VolumeHidingXorEMMUtils {

    public static final Random random = new Random();
    public static int R = 3;

    public static Stack<PairNumber> doMappingStep(
            final SecretKey prfKey, final Map<Label, Set<Plaintext>> multimap) throws IOException {
        final var stack = new Stack<PairNumber>();
        final var queue = new LinkedList<Integer>();
        final var table = new ArrayList<LinkedList<PairLabelPlaintext>>();
        final var labels = multimap.keySet();
        for (final var label : labels) {
            final var values = multimap.get(label);
            for (final var value : values) {
                final var pair = new PairLabelPlaintext(label, value);
                insertPair(pair, table, prfKey, multimap.size());
            }
        }
        table.forEach(
                el -> {
                    if (el.size() == 1) {
                        queue.offer(table.indexOf(el));
                    }
                });
        while (!queue.isEmpty()) {
            final var i = queue.poll();
            final var pair = table.get(i).get(0);
            stack.push(new PairNumber(pair, i));
            removePair(pair, table, prfKey, multimap.size(), queue);
        }
        if (stack.size() != multimap.size()) {
            return null;
        }
        return stack;
    }

    private static void insertPair(
            final PairLabelPlaintext pair,
            final List<LinkedList<PairLabelPlaintext>> table,
            final SecretKey prfKey,
            final int tableSize)
            throws IOException {
        for (int i = 0; i < R; i++) {
            final var index = calculateIndex(pair, prfKey, i, tableSize);
            if (table.get(index) == null) {
                table.set(index, new LinkedList<>());
            }
            final var list = table.get(index);
            list.add(pair);
            table.set(index, list);
        }
    }

    private static void removePair(
            final PairLabelPlaintext pair,
            final List<LinkedList<PairLabelPlaintext>> table,
            final SecretKey prfKey,
            final int tableSize,
            final Queue<Integer> queue)
            throws IOException {
        for (int i = 0; i < R; i++) {
            final var index = calculateIndex(pair, prfKey, i, tableSize);
            final var list = table.get(index);
            list.remove(pair);
            table.set(index, list);
            if (list.size() == 1) {
                queue.offer(index);
            }
        }
    }

    public static int calculateIndex(
            final PairLabelPlaintext pair, final SecretKey prfKey, final int t, final int tableSize)
            throws IOException {
        return Math.floorMod(
                CastingHelpers.fromByteArrayToInt(
                        DPRF.calculateFk(
                                CastingHelpers.fromByteArrayToBitInputStream(
                                        org.bouncycastle.util.Arrays.concatenate(
                                                pair.label().label(),
                                                pair.value().data(),
                                                CastingHelpers.fromIntToByteArray(t))),
                                prfKey.getEncoded())),
                tableSize);
    }

    public static byte[] drawRandomOfLength(final int n) {
        final var bytes = new byte[n];
        random.nextBytes(bytes);
        return bytes;
    }

    public static byte[] XOR(final byte[] el1, final byte[] el2) {
        final int n = Math.min(el1.length, el2.length);
        final var result = new byte[n];
        final var el1Trunc = Arrays.copyOfRange(el1, 0, n);
        final var el2Trunc = Arrays.copyOfRange(el2, 0, n);
        for (int i = n - 1; i >= 0; i--) {
            result[i] = Byte.parseByte(String.valueOf(el1Trunc[i] ^ el2Trunc[i]));
        }
        return result;
    }
}
