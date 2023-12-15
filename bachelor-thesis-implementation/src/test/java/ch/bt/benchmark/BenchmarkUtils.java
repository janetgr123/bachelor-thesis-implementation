package ch.bt.benchmark;

import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.encryptedindex.EncryptedIndexMap;
import ch.bt.model.encryptedindex.EncryptedIndexTables;
import ch.bt.model.multimap.CiphertextWithIV;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.PairLabelCiphertext;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.bt.model.searchtoken.SearchToken;
import ch.bt.model.searchtoken.SearchTokenBytes;
import ch.bt.model.searchtoken.SearchTokenInts;
import ch.bt.model.searchtoken.SearchTokenListInts;
import ch.qos.logback.core.encoder.ByteArrayUtil;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;

import java.io.*;
import java.util.*;

public class BenchmarkUtils {

    public static Vertex readRoot(final int dataSize, final String type) throws IOException {
        final var current =
                String.join(
                        "/", BenchmarkSettings.FOLDER, String.join("-", "root", "build-index.csv"));
        final var file = new File(current);
        if (file.exists()) {
            Reader in = new FileReader(current);
            CSVFormat csvFormat =
                    CSVFormat.DEFAULT
                            .builder()
                            .setHeader("type", "data size", "root id", "root from", "root to")
                            .setSkipHeaderRecord(true)
                            .build();
            Iterable<CSVRecord> records = csvFormat.parse(in);
            List<CSVRecord> recordList = new ArrayList<>();
            records.forEach(record -> recordList.add(record));
            final var entry =
                    recordList.stream()
                            .filter(
                                    el ->
                                            el.get("type").equals(type)
                                                    && el.get("data size")
                                                            .equals(String.valueOf(dataSize)))
                            .toList()
                            .get(0);
            return new Vertex(
                    entry.get("root id"),
                    new CustomRange(
                            Integer.parseInt(entry.get("root from")),
                            Integer.parseInt(entry.get("root to"))));
        }
        return null;
    }

    public static Map<Integer, List<SearchToken>> extractToken(
            final int dataSize, final String type, final int rangeSize) throws IOException {
        final Map<Integer, List<SearchToken>> result = new HashMap<>();
        final var current =
                String.join("/", BenchmarkSettings.FOLDER, String.join("-", "token", "trapdoor"));
        final var file = new File(current);
        if (file.exists()) {
            Reader in = new FileReader(current);
            CSVFormat csvFormat =
                    CSVFormat.DEFAULT
                            .builder()
                            .setHeader("type", "data size", "range size", "token")
                            .setSkipHeaderRecord(true)
                            .build();
            Iterable<CSVRecord> records = csvFormat.parse(in);
            List<CSVRecord> recordList = new ArrayList<>();
            records.forEach(record -> recordList.add(record));
            final var entries =
                    recordList.stream()
                            .filter(
                                    el ->
                                            el.get("type").equals(type)
                                                    && el.get("data size")
                                                            .equals(String.valueOf(dataSize))
                                                    && el.get("range size")
                                                            .equals(String.valueOf(rangeSize)))
                            .toList();
            for (final var entry : entries) {
                final var tokenList = Arrays.asList(entry.get("token").split(","));
                final List<SearchToken> t =
                        switch (type) {
                            case "volumeHiding" -> tokenList.stream()
                                    .map(el -> new SearchTokenListInts(extractList(el)))
                                    .map(SearchToken.class::cast)
                                    .toList();
                            default -> tokenList.stream()
                                    .map(ByteArrayUtil::hexStringToByteArray)
                                    .map(SearchTokenBytes::new)
                                    .map(SearchToken.class::cast)
                                    .toList();
                        };
                result.put(Integer.parseInt(entry.get("from")), t);
            }
        }
        return result;
    }

    private static List<SearchTokenInts> extractList(final String token) {
        return Arrays.stream(token.split("\\|"))
                .filter(s -> !s.isEmpty())
                .map(
                        pair ->
                                Arrays.stream(pair.split(","))
                                        .map(BenchmarkUtils::extractInts)
                                        .toList())
                .map(k -> new SearchTokenInts(k.get(0), k.get(1)))
                .toList();
    }

    private static Integer extractInts(final String el) {
        if (el.startsWith("(")) {
            return Integer.parseInt(el.substring(1));
        } else if (el.endsWith(")")) {
            return Integer.parseInt(el.substring(0, 1));
        }
        return 0;
    }

    public static EncryptedIndex extractIndex(final int dataSize, final String type)
            throws IOException {
        EncryptedIndex result = null;
        final var current =
                String.join(
                        "/",
                        BenchmarkSettings.FOLDER,
                        String.join("-", "encryptedIndex", "build-index.csv"));
        final var file = new File(current);
        if (file.exists()) {
            Reader in = new FileReader(current);
            CSVFormat csvFormat =
                    CSVFormat.DEFAULT
                            .builder()
                            .setHeader(
                                    "type",
                                    "data size",
                                    "label data",
                                    "label iv",
                                    "value1 data",
                                    "value1 iv")
                            .setSkipHeaderRecord(true)
                            .build();
            Iterable<CSVRecord> records = csvFormat.parse(in);
            List<CSVRecord> recordList = new ArrayList<>();
            records.forEach(record -> recordList.add(record));
            final var entries =
                    recordList.stream()
                            .filter(
                                    el ->
                                            el.get("type").equals(type)
                                                    && el.get("data size")
                                                            .equals(String.valueOf(dataSize)))
                            .toList();
            final var map = new HashMap<Label, CiphertextWithIV>();
            final var table1 = new ArrayList<PairLabelCiphertext>();
            final var table2 = new ArrayList<PairLabelCiphertext>();
            for (final var entry : entries) {
                final var label =
                        switch (type) {
                            case "volumeHiding", "volumeHidingOpt" -> new CiphertextWithIV(
                                    ByteArrayUtil.hexStringToByteArray(entry.get("label iv")),
                                    ByteArrayUtil.hexStringToByteArray(entry.get("label data")));
                            default -> new Label(
                                    ByteArrayUtil.hexStringToByteArray(entry.get("label data")));
                        };
                final var value =
                        new CiphertextWithIV(
                                ByteArrayUtil.hexStringToByteArray(entry.get("value1 iv")),
                                ByteArrayUtil.hexStringToByteArray(entry.get("value1 data")));
                switch (type) {
                    case "volumeHiding", "volumeHidingOpt":
                        boolean tableNumber =
                                entry.get("tableNumber").equals("0")
                                        ? table1.add(
                                                new PairLabelCiphertext(
                                                        (CiphertextWithIV) label, value))
                                        : table2.add(
                                                new PairLabelCiphertext(
                                                        (CiphertextWithIV) label, value));
                        break;
                    default:
                        map.put((Label) label, value);
                }
                result =
                        switch (type) {
                            case "volumeHiding", "volumeHidingOpt" -> new EncryptedIndexTables(
                                    table1.toArray(PairLabelCiphertext[]::new),
                                    table2.toArray(PairLabelCiphertext[]::new));
                            default -> new EncryptedIndexMap(map);
                        };
            }
        }
        return result;
    }
}
