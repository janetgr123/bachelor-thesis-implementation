package ch.bt;

import ch.bt.crypto.CastingHelpers;
import ch.bt.model.multimap.Label;
import ch.bt.model.multimap.Plaintext;
import ch.bt.model.rc.Vertex;
import ch.bt.rc.RangeCoverUtils;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;
import java.util.stream.Stream;

public class TestUtils {

    public static final int TEST_DATA_SET_SIZE = 100;
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
            multimap = getDataFromDB(connection);
            root = RangeCoverUtils.getRoot(multimap);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        final var labels = multimap.keySet().stream().toList();
        final var randomLabelId = (int) ((labels.size() - 1) * Math.random());
        searchLabel = labels.get(randomLabelId);
        generateTwoSmallMultimaps();
    }

    public static Map<Label, Set<Plaintext>> getDataFromDB(Connection connection)
            throws SQLException {
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery("select pk_node_id, longitude from t_network_nodes");
        final Map<Label, Set<Plaintext>> multiMap = new HashMap<>();
        // Reduce test data
        int i = 0;
        while (rs.next() && i < TEST_DATA_SET_SIZE) {
            final var set = new HashSet<Plaintext>();
            set.add(
                    new Plaintext(
                            CastingHelpers.fromIntToByteArray(
                                    (int) (Math.pow(10, 6) * rs.getDouble("longitude")))));
            multiMap.put(
                    new Label(CastingHelpers.fromIntToByteArray(rs.getInt("pk_node_id"))), set);
            i++;
        }
        return multiMap;
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
