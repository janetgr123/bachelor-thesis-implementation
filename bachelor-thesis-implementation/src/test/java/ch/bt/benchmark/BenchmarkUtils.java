package ch.bt.benchmark;

import ch.bt.crypto.CastingHelpers;
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

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;

import java.io.*;
import java.util.*;
import java.util.function.Predicate;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class BenchmarkUtils {

    public static void deleteHelperFile(final String filename) {
        final var file = new File(String.join("/", BenchmarkSettings.FOLDER, filename));
        if (file.exists()) {
            final var success = file.delete();
            System.out.println("Deletion successful: " + success);
        } else {
            System.out.println("FILE DOES NOT EXIST");
        }
    }

    private static List<CSVRecord> readMultimapParams(final String type) throws IOException {
        if (type.equals("baseline")) {
            return List.of();
        }
        final var current =
                String.join(
                        "/",
                        BenchmarkSettings.FOLDER,
                        String.join("-", "results", "build-index.csv"));
        final var file = new File(current);
        if (file.exists()) {
            Reader in = new FileReader(current);
            CSVFormat csvFormat =
                    CSVFormat.DEFAULT
                            .builder()
                            .setHeader(
                                    "type",
                                    "data size",
                                    "multimap size",
                                    "encrypted index size",
                                    "dummy entries in encrypted index",
                                    "max number of values per label multimap",
                                    "number of values multimap",
                                    "prf key",
                                    "aes key")
                            .setSkipHeaderRecord(true)
                            .build();
            Iterable<CSVRecord> records = csvFormat.parse(in);
            List<CSVRecord> recordList = new ArrayList<>();
            records.forEach(recordList::add);
            return recordList;
        }
        return List.of();
    }

    public static List<Integer> readSizes(final int dataSize, final String type)
            throws IOException {
        final var recordList = readMultimapParams(type);
        final var entry =
                recordList.stream()
                        .filter(
                                el ->
                                        el.get("type").equals(type)
                                                && el.get("data size")
                                                        .equals(String.valueOf(dataSize)))
                        .toList()
                        .get(0);
        return List.of(
                Integer.parseInt(entry.get("max number of values per label multimap")),
                Integer.parseInt(entry.get("number of values multimap")));
    }

    public static List<SecretKey> getKeys(final int dataSize, final String type)
            throws IOException {
        final var recordList = readMultimapParams(type);
        final var entry =
                recordList.stream()
                        .filter(
                                el ->
                                        el.get("type").equals(type)
                                                && el.get("data size")
                                                        .equals(String.valueOf(dataSize)))
                        .toList()
                        .get(0);
        return List.of(
                new SecretKeySpec(
                        CastingHelpers.fromStringToByteArray(entry.get("prf key")), "HMacSHA512"),
                new SecretKeySpec(
                        CastingHelpers.fromStringToByteArray(entry.get("aes key")), "AES"));
    }

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
            records.forEach(recordList::add);
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
                String.join(
                        "/", BenchmarkSettings.FOLDER, String.join("-", "token", "trapdoor.csv"));
        final var file = new File(current);
        if (file.exists()) {
            Reader in = new FileReader(current);
            CSVFormat csvFormat =
                    CSVFormat.DEFAULT
                            .builder()
                            .setHeader("type", "data size", "range size", "from", "token")
                            .setSkipHeaderRecord(true)
                            .build();
            Iterable<CSVRecord> records = csvFormat.parse(in);
            List<CSVRecord> recordList = new ArrayList<>();
            records.forEach(recordList::add);
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
                final var tokenList = entry.get("token");
                final List<SearchToken> t =
                        switch (type) {
                            case "volumeHiding" -> List.of(
                                    (SearchToken) new SearchTokenListInts(extractList(tokenList)));

                            default -> Arrays.stream(tokenList.split(","))
                                    .map(CastingHelpers::fromStringToByteArray)
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
        return Arrays.stream(token.split("\\("))
                .filter(Predicate.not(String::isEmpty))
                .map(BenchmarkUtils::extractInts)
                .map(k -> new SearchTokenInts(k.get(0), k.get(1)))
                .toList();
    }

    private static List<Integer> extractInts(final String el) {
        final var ints =
                Arrays.stream(el.split(",")).filter(Predicate.not(String::isEmpty)).toList();
        final String withBracket = ints.get(1);
        return List.of(
                Integer.parseInt(ints.get(0)),
                Integer.parseInt(withBracket.substring(0, withBracket.length() - 1)));
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
                                    "tableNumber",
                                    "data size",
                                    "label data",
                                    "label iv",
                                    "value1 data",
                                    "value1 iv")
                            .setSkipHeaderRecord(true)
                            .build();
            Iterable<CSVRecord> records = csvFormat.parse(in);
            List<CSVRecord> recordList = new ArrayList<>();
            records.forEach(recordList::add);
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
                                    CastingHelpers.fromStringToByteArray(entry.get("label iv")),
                                    CastingHelpers.fromStringToByteArray(entry.get("label data")));
                            default -> new Label(
                                    CastingHelpers.fromStringToByteArray(entry.get("label data")));
                        };
                final var value =
                        new CiphertextWithIV(
                                CastingHelpers.fromStringToByteArray(entry.get("value1 iv")),
                                CastingHelpers.fromStringToByteArray(entry.get("value1 data")));
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
