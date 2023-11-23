package ch.bt;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.security.Security;

/**
 * <a
 * href="https://stackoverflow.com/questions/43282798/in-junit-5-how-to-run-code-before-all-tests">...</a>
 * date accessed: 22.11.2023
 *
 * <p><a href="https://www.baeldung.com/docker-test-containers">...</a> date accessed: 22.11.2023
 */
public class TestConfigurations implements BeforeAllCallback {
    private static boolean started = false;

    @Override
    public void beforeAll(ExtensionContext extensionContext) {
        if (!started) {
            started = true;
            Security.addProvider(new BouncyCastleFipsProvider());
            extensionContext
                    .getRoot()
                    .getStore(ExtensionContext.Namespace.GLOBAL)
                    .put("test configurations", this);
        }
    }
}
