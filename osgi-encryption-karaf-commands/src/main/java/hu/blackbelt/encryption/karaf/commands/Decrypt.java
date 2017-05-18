package hu.blackbelt.encryption.karaf.commands;

import org.apache.karaf.shell.api.action.*;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.EnvironmentStringPBEConfig;

/**
 * Apache Karaf command to decrypt a string.
 */
@Command(scope = "jasypt", name = "decrypt", description = "Decrypt String value.")
@Service
public class Decrypt implements Action {
    
    @Argument(index = 0, name = "text", description = "Text to decrypt", required = true, multiValued = false)
    private String text;
    
    @Option(name = "--algorithm", description = "Algorithm of encryption", required = true, multiValued = false)
    @Completion(PBEAlgorithmCompleter.class)
    private String algorithm;

    @Option(name = "--provider", description = "Provider name", required = false, multiValued = false)
    private String providerName;

    @Option(name = "--password", description = "Password for encryption", required = false, multiValued = false)
    private String password;

    @Option(name = "--password-env", description = "Password environment variable for encryption", required = false, multiValued = false)
    private String passwordEnvName;

    @Option(name = "--password-prop", description = "Password system property for encryption", required = false, multiValued = false)
    private String passwordSysPropertyName;
    
    @Option(name = "--outputType", description = "Output type", required = false, multiValued = false)
    @Completion(OutputTypeCompleter.class)
    private String outputType = OutputTypeCompleter.BASE64;

    @Override
    public Object execute() {
        final StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        final EnvironmentStringPBEConfig config = new EnvironmentStringPBEConfig();
        config.setAlgorithm(algorithm);
        if (providerName != null) {
            config.setProviderName(providerName);
        }
        if (password != null) {
            config.setPassword(password);
        } else if (passwordEnvName != null) {
            config.setPasswordEnvName(passwordEnvName);
        } else if (passwordSysPropertyName != null) {
            config.setPasswordEnvName(passwordSysPropertyName);
        }
        config.setStringOutputType(outputType);
        encryptor.setConfig(config);
        
        System.out.println("Decrypted value is: " + encryptor.decrypt(text));

        return null;
    }
}
