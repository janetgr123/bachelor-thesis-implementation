package ch.bt;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * <a
 * href="https://stackoverflow.com/questions/43282798/in-junit-5-how-to-run-code-before-all-tests">...</a>
 */
public class TestConfigurations implements BeforeAllCallback {
    private static boolean started = false;
    public static Connection connection;

    @Override
    public void beforeAll(ExtensionContext extensionContext) {
        if (!started) {
            started = true;
            Security.addProvider(new BouncyCastleFipsProvider());
            try {
                connection =
                        DriverManager.getConnection(
                                "jdbc:postgresql://localhost:5432/bt", "bt", "bt");
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
            TestUtils.init();
            extensionContext
                    .getRoot()
                    .getStore(ExtensionContext.Namespace.GLOBAL)
                    .put("test configurations", this);
        }
    }
}
