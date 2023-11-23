package ch.bt;


import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.security.Security;

/**
 * <a
 * href="https://stackoverflow.com/questions/43282798/in-junit-5-how-to-run-code-before-all-tests">...</a>
 * <a href="https://www.baeldung.com/docker-test-containers">...</a> <a
 * href="https://github.com/mikemybytes/squash-db-migrations">...</a>
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
