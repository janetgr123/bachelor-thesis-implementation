package ch.bt;

import ch.bt.model.Label;
import ch.bt.model.Plaintext;
import ch.bt.model.rc.CustomRange;
import ch.bt.model.rc.Vertex;
import ch.bt.rc.RangeCoverUtils;

import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.DirectedAcyclicGraph;

import java.math.BigInteger;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;
import java.util.stream.Stream;

public class TestUtils {
    public static final double ALPHA = 0.3;

    public static final List<Integer> VALID_SECURITY_PARAMETERS_FOR_AES = List.of(128, 256);

    public static final List<Integer> INVALID_SECURITY_PARAMETERS_FOR_AES = List.of(512);

    public static final List<Integer> VALID_SECURITY_PARAMETERS_FOR_HMAC = List.of(128, 256, 512);

    public static Map<Label, Set<Plaintext>> multimap = new HashMap<>();

    public static Label searchLabel;

    public static Graph<Vertex, DefaultEdge> graph;

    public static Vertex root;

    public static void init() {
        try {
            multimap = getDataFromDB();
            graph = generateGraph(multimap);
            final var intervalsWith0 =
                    graph.vertexSet().stream()
                            .filter(el -> el.id().startsWith("0-"))
                            .map(Vertex::range)
                            .map(CustomRange::getMaximum)
                            .sorted()
                            .toList();
            root =
                    RangeCoverUtils.getVertex(
                            graph,
                            String.join(
                                    "-",
                                    "0",
                                    intervalsWith0.get(intervalsWith0.size() - 1).toString()));
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        final var labels = multimap.keySet().stream().toList();
        final var randomLabelId = (int) ((labels.size() - 1) * Math.random());
        searchLabel = labels.get(randomLabelId);
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

    public static Stream<Integer> getValidSecurityParametersForAES() {
        return VALID_SECURITY_PARAMETERS_FOR_AES.stream();
    }

    public static Stream<Integer> getValidSecurityParametersForHmac() {
        return VALID_SECURITY_PARAMETERS_FOR_HMAC.stream();
    }

    public static Stream<Integer> getInvalidSecurityParametersForAES() {
        return INVALID_SECURITY_PARAMETERS_FOR_AES.stream();
    }

    public static Graph<Vertex, DefaultEdge> generateGraph(
            final Map<Label, Set<Plaintext>> multiMap) {
        final var graph = new DirectedAcyclicGraph<Vertex, DefaultEdge>(DefaultEdge.class);
        final Set<Vertex> vertices = new HashSet<>();
        int n = 0;
        final var keys = multiMap.keySet();
        for (final var key : keys) {
            final var values = multiMap.get(key);
            n += values.size();
        }
        final var size = (int) Math.ceil(Math.log(n) / Math.log(2));
        for (int i = 0; i < size + 1; i++) {
            RangeCoverUtils.addVerticesAndEdgesForLevel(vertices, graph, i, n);
        }
        return graph;
    }
}
