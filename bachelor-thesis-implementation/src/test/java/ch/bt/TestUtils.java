package ch.bt;

import ch.bt.model.Label;
import ch.bt.model.Plaintext;

import java.math.BigInteger;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;
import java.util.stream.Stream;

public class TestUtils {

    private static final int MAX_NUMBER_OF_LABELS = 100;
    private static final int MAX_SIZE_VALUE_SET = 10;

    public static final List<Integer> VALID_SECURITY_PARAMETERS_FOR_AES = List.of(128, 256);

    public static final List<Integer> INVALID_SECURITY_PARAMETERS_FOR_AES = List.of(512);

    public static final List<Integer> VALID_SECURITY_PARAMETERS_FOR_HMAC = List.of(128, 256, 512);

    public static final Map<Integer, Map<Label, Set<Plaintext>>> multimaps = new HashMap<>();


    public static final Map<Integer, Label> searchLabels = new HashMap<>();

    public static void init(){
        VALID_SECURITY_PARAMETERS_FOR_AES
                .forEach(
                        securityParameter -> {
                            try {
                                multimaps.put(securityParameter, TestUtils.getDataFromDB());
                            } catch (SQLException e) {
                                throw new RuntimeException(e);
                            }
                            searchLabels.put(
                                    securityParameter,
                                    new Label(
                                            BigInteger.valueOf((int) (20 * Math.random()))
                                                    .toByteArray()));
                        });
    }

    public static Map<Label, Set<Plaintext>> getDataFromDB() throws SQLException {
        Statement stmt = TestConfigurations.connection.createStatement();
        ResultSet rs = stmt.executeQuery("select pk_node_id, latitude from t_network_nodes");
        final Map<Label, Set<Plaintext>> multiMap = new HashMap<>();
        while (rs.next()) {
            final var set = new HashSet<Plaintext>();
            set.add(
                    new Plaintext(
                            BigInteger.valueOf((int) (Math.pow(10, 6) * rs.getDouble("latitude")))
                                    .toByteArray()));
            multiMap.put(new Label(BigInteger.valueOf(rs.getInt("pk_node_id")).toByteArray()), set);
        }
        return multiMap;
    }

    public static Label buildMultiMapAndGenerateRandomSearchLabel(final int securityParameter) {
        final Map<Label, Set<Plaintext>> multimap = new HashMap<>();
        Label searchLabel = null;
        Random random = new Random();
        int index = (int) (MAX_NUMBER_OF_LABELS * Math.random()) + 1;
        while (multimap.size() < MAX_NUMBER_OF_LABELS) {
            final var values = new HashSet<Plaintext>();
            int size = (int) (MAX_SIZE_VALUE_SET * Math.random()) + 1;
            while (values.size() < size) {
                byte[] v = new byte[securityParameter];
                random.nextBytes(v);
                values.add(new Plaintext(v));
            }
            byte[] l = new byte[securityParameter];
            random.nextBytes(l);
            final var label = new Label(l);
            multimap.put(label, values);
            if (multimap.size() == index) {
                searchLabel = label;
            }
        }
        multimaps.put(securityParameter, multimap);
        return searchLabel;
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
}
