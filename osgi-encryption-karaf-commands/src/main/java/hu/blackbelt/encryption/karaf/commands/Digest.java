package hu.blackbelt.encryption.karaf.commands;

import org.apache.karaf.shell.api.action.*;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.jasypt.digest.StandardStringDigester;
import org.jasypt.digest.config.EnvironmentStringDigesterConfig;

/**
 * Apache Karaf command to calculate/validate digest of a string.
 */
@Command(scope = "jasypt", name = "digest", description = "Get digest of a String.")
@Service
public class Digest implements Action {
    
    @Argument(index = 0, name = "text", description = "Text to encrypt", required = true, multiValued = false)
    private String text;

    @Option(name = "--algorithm", description = "Digest method", required = false, multiValued = false)
    @Completion(DigestAlgorithmCompleter.class)
    private String algorithm = "SHA";

    @Option(name = "--provider", description = "Provider name", required = false, multiValued = false)
    private String providerName;

    @Option(name = "--digest", description = "Digest value for validation", required = false, multiValued = false)
    private String digest;
    
    @Option(name = "--saltSize", description = "Salt size", required = false, multiValued = false)
    private Integer saltSize;
    
    @Option(name = "--iterations", description = "Iterations", required = false, multiValued = false)
    private Integer iterations;
    
    @Option(name = "--outputType", description = "Output type", required = false, multiValued = false)
    @Completion(OutputTypeCompleter.class)
    private String outputType = OutputTypeCompleter.HEXADECIMAL;

    @Override
    public Object execute() {
        final StandardStringDigester digester = new StandardStringDigester();
        final EnvironmentStringDigesterConfig config = new EnvironmentStringDigesterConfig();
        config.setAlgorithm(algorithm);
        if (providerName != null) {
            config.setProviderName(providerName);
        }
        if (saltSize != null) {
            config.setSaltSizeBytes(saltSize);
        }
        if (iterations != null) {
            config.setIterations(iterations);
        }
        config.setStringOutputType(outputType);
        digester.setConfig(config);

        if (digest != null) {
            final boolean matches = digester.matches(text, digest);
            System.out.println("Validation result: " + matches);
        } else {
            System.out.println("Digest value is: " + digester.digest(text));
        }

        return null;
    }
}
