package hu.blackbelt.encryption.services.impl;

import hu.blackbelt.encryption.services.Encryptor;
import lombok.extern.slf4j.Slf4j;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.EnvironmentStringPBEConfig;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.annotations.*;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.AttributeType;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Dictionary;
import java.util.Hashtable;

@Component(immediate = true, configurationPolicy = ConfigurationPolicy.REQUIRE, service = Encryptor.class)
@Designate(ocd = StringEncryptor.Config.class)
@Slf4j
public class StringEncryptor implements Encryptor, org.jasypt.encryption.StringEncryptor {

    @SuppressWarnings("checkstyle:JavadocMethod")
    @ObjectClassDefinition(name = "String encryptor configuration")
    public @interface Config {

        @AttributeDefinition(required = false, name = "Encryption algorithm")
        String encryption_algorithm() default DEFAULT_ENCRYPTION_ALGORITHM;

        @AttributeDefinition(required = false, name = "Password for encryption", type = AttributeType.PASSWORD)
        String encryption_password();

        @AttributeDefinition(required = false, name = "Password file for encryption")
        String encryption_passwordFile();

        @AttributeDefinition(required = false, name = "Environment variable holding encryption algorithm")
        String encryption_passwordEnvName() default DEFAULT_ENCRYPTION_PASSWORD_ENV_NAME;

        @AttributeDefinition(required = false, name = "Alias for encryptor")
        String encryptor_alias();
    }

    /**
     * Algorithm of default StringEncryptor.
     */
    public static final String DEFAULT_ENCRYPTION_ALGORITHM = "PBEWithSHA1AndDESEDE";

    /**
     * Environment variable of password for default StringEncryptor.
     */
    public static final String DEFAULT_ENCRYPTION_PASSWORD_ENV_NAME = "ENCRYPTION_PASSWORD";

    private ServiceRegistration<org.jasypt.encryption.StringEncryptor> defaultStringEncryptor;

    private StandardPBEStringEncryptor encryptor;

    /**
     * Register StringEncryptor service instance.
     *
     * @param context bundle context
     * @param config  configuration options
     */
    @Activate
    public void start(final BundleContext context, final Config config) {
        encryptor = new StandardPBEStringEncryptor();
        final EnvironmentStringPBEConfig encryptorConfig = new EnvironmentStringPBEConfig();
        encryptorConfig.setAlgorithm(config.encryption_algorithm());
        if (config.encryption_password() != null) {
            encryptorConfig.setPassword(config.encryption_password());
        } else if (config.encryption_passwordFile() != null) {
            encryptorConfig.setPassword(loadPassword(config.encryption_passwordFile()));
        } else if (config.encryption_passwordEnvName() != null) {
            encryptorConfig.setPasswordEnvName(config.encryption_passwordEnvName());
        }
        encryptor.setConfig(encryptorConfig);

        final Dictionary<String, Object> dict = new Hashtable<>();
        dict.put(Constants.SERVICE_RANKING, Integer.MAX_VALUE);
        dict.put("algorithm", config.encryption_algorithm());
        if (config.encryptor_alias() != null) {
            dict.put("alias", config.encryptor_alias());
        }
        defaultStringEncryptor = context.registerService(org.jasypt.encryption.StringEncryptor.class, encryptor, dict);
    }

    /**
     * Unregister StringEncryptor service instance.
     */
    @Deactivate
    public void stop() {
        encryptor = null;
        try {
            if (defaultStringEncryptor != null) {
                defaultStringEncryptor.unregister();
            }
        } finally {
            defaultStringEncryptor = null;
        }
    }

    @Override
    public String encrypt(final String message) {
        return encryptor.encrypt(message);
    }

    @Override
    public String decrypt(final String encryptedMessage) {
        return encryptor.decrypt(encryptedMessage);
    }

    /**
     * Load password from file.
     *
     * @param file file that contains password, using default charset of platform
     * @return plain text password
     */
    private static String loadPassword(final String file) {
        try {
            byte[] encoded = Files.readAllBytes(Paths.get(file));
            return new String(encoded, Charset.defaultCharset());
        } catch (IOException ex) {
            throw new IllegalArgumentException("Unable to read password from file: " + file, ex);
        }
    }
}
