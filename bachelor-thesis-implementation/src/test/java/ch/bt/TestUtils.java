package ch.bt;

import ch.bt.crypto.CastingHelpers;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.rc.Vertex;
import ch.bt.rc.RangeCoverUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.*;
import java.util.stream.Stream;

public class TestUtils {

    private static final Logger logger = LoggerFactory.getLogger(TestUtils.class);
    public static final int TEST_DATA_SET_SIZE = 10;
    public static final int TEST_DATA = 0;
    public static final double ALPHA = 0.3;

    public static final List<Integer> VALID_SECURITY_PARAMETERS_FOR_AES = List.of(128, 256);

    public static final List<Integer> INVALID_SECURITY_PARAMETERS_FOR_AES = List.of(512);

    public static final List<Integer> VALID_SECURITY_PARAMETERS_FOR_HMAC = List.of(128, 256, 512);

    public static Map<Label, Set<Plaintext>> multimap = new HashMap<>();
    public static Map<Label, Set<Plaintext>> multimapSmall = new HashMap<>();
    public static Map<Label, Set<Plaintext>> multimapSmall2 = new HashMap<>();

    public static Label searchLabel;

    public static Vertex root;

    public static void init(Connection connection) {
        try {
            multimap = sampleDataFromDB(connection, TEST_DATA_SET_SIZE, TEST_DATA);
            root = RangeCoverUtils.getRoot(multimap);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        final var labels = multimap.keySet().stream().toList();
        final var randomLabelId = (int) ((labels.size() - 1) * Math.random());
        searchLabel = labels.get(randomLabelId);
        generateTwoSmallMultimaps();
        logger.info("initialization done");
    }

    public static Map<Label, Set<Plaintext>> sampleDataFromDB(
            Connection connection, final int size, final int dataset) throws SQLException {
        final String primaryKey =
                switch (dataset) {
                    case 0 -> "pk_node_id";
                    default -> "pk_id";
                };
        final String table =
                switch (dataset) {
                    case 1 -> "t_spitz";
                    case 2 -> "t_check_ins";
                    default -> "t_network_nodes";
                };
        logger.info("sample {} data points", size);
        final var PUFFER = (int) Math.round(0.2 * size);
        Statement stmt = connection.createStatement();
        ResultSet rs0 =
                stmt.executeQuery(
                        "select min("
                                + primaryKey
                                + ") as min, max("
                                + primaryKey
                                + ") as max from "
                                + table);
        rs0.next();
        final var min = rs0.getInt("min");
        final var max = rs0.getInt("max");
        final var indices = new ArrayList<Integer>();
        while (indices.size() < size + PUFFER) {
            indices.add((int) Math.round(Math.random() * max + min));
        }
        final var query =
                "select "
                        + primaryKey
                        + ", longitude from "
                        + table
                        + " where "
                        + primaryKey
                        + " in ("
                        + outputList(indices.stream().sorted().toList())
                        + ")";
        ResultSet rs = stmt.executeQuery(query);
        final Map<Label, Set<Plaintext>> multiMap = new HashMap<>();
        while (rs.next() && multiMap.size() < size) {
            final var set = new HashSet<Plaintext>();
            set.add(
                    new Plaintext(
                            CastingHelpers.fromIntToByteArray(
                                    (int)
                                            Math.round(
                                                    Math.pow(10, 6) * rs.getDouble("longitude")))));
            multiMap.put(new Label(CastingHelpers.fromIntToByteArray(rs.getInt(primaryKey))), set);
        }
        logger.info("sampling done");
        return multiMap;
    }

    private static String outputList(final List<Integer> list) {
        StringBuilder result = new StringBuilder();
        for (final var l : list) {
            result.append(l);
            result.append(",");
        }
        result.deleteCharAt(result.length() - 1);
        return result.toString();
    }

    public static Stream<Integer> getValidSecurityParametersForAES() {
        return VALID_SECURITY_PARAMETERS_FOR_AES.stream();
    }

    public static Stream<Integer> getValidSecurityParametersForHmac() {
        return VALID_SECURITY_PARAMETERS_FOR_HMAC.stream();
    }

    public static Stream<Integer> getInvalidSecurityParametersForAES() {
        return INVALID_SECURITY_PARAMETERS_FOR_AES.stream();
    }

    public static void generateTwoSmallMultimaps() {
        final var set1 = new HashSet<Plaintext>();
        final List<Plaintext> plaintexts = new ArrayList<>();
        plaintexts.add(new Plaintext(new byte[] {0}));
        plaintexts.add(new Plaintext(new byte[] {1}));
        plaintexts.add(new Plaintext(new byte[] {2}));
        plaintexts.add(new Plaintext(new byte[] {3}));
        plaintexts.add(new Plaintext(new byte[] {4}));
        plaintexts.add(new Plaintext(new byte[] {5}));
        final List<Label> labels = new ArrayList<>();
        labels.add(new Label(new byte[] {0}));
        labels.add(new Label(new byte[] {1}));
        labels.add(new Label(new byte[] {2}));
        labels.add(new Label(new byte[] {3}));
        labels.add(new Label(new byte[] {4}));
        labels.add(new Label(new byte[] {5}));
        set1.add(plaintexts.get(0));
        set1.add(plaintexts.get(1));
        set1.add(plaintexts.get(2));
        multimapSmall.put(labels.get(0), set1);
        multimapSmall2.put(labels.get(0), set1);
        final var set2 = new HashSet<>(plaintexts);
        multimapSmall.put(labels.get(1), set2);
        multimapSmall2.put(labels.get(1), set2);
        multimapSmall.put(labels.get(2), set2);
        multimapSmall.put(labels.get(3), set2);
        multimapSmall.put(labels.get(4), set2);
        multimapSmall.put(labels.get(5), set2);
    }
}
