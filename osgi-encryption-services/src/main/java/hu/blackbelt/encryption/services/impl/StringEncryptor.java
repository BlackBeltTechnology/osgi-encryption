package hu.blackbelt.encryption.services.impl;

import hu.blackbelt.encryption.services.Encryptor;
import lombok.extern.slf4j.Slf4j;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.EnvironmentStringPBEConfig;
import org.jasypt.encryption.pbe.config.SimplePBEConfig;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.annotations.*;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.AttributeType;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@Component(immediate = true, configurationPolicy = ConfigurationPolicy.REQUIRE)
@Designate(ocd = StringEncryptor.Config.class)
@Slf4j
public class StringEncryptor implements Encryptor {

    private AtomicLong encryptionTime = new AtomicLong();
    private AtomicLong decyptionTime = new AtomicLong();

    private AtomicInteger encryptionErrors = new AtomicInteger();
    private AtomicInteger decryptionErrors = new AtomicInteger();

    private AtomicInteger encryptionCount = new AtomicInteger();
    private AtomicInteger decryptionCount = new AtomicInteger();

    @SuppressWarnings("checkstyle:JavadocMethod")
    @ObjectClassDefinition(name = "String encryptor configuration")
    public @interface Config {

        @AttributeDefinition(name = "Encryption algorithm")
        String encryption_algorithm();

        @AttributeDefinition(required = false, name = "Password for encryption", type = AttributeType.PASSWORD)
        String encryption_password();

        @AttributeDefinition(required = false, name = "Password file for encryption")
        String encryption_passwordFile();

        @AttributeDefinition(required = false, name = "Environment variable holding password for encryption")
        String encryption_passwordEnvName();

        @AttributeDefinition(required = false, name = "JVM argument holding password for encryption")
        String encryption_passwordSysPropertyName();

        @AttributeDefinition(required = false, name = "Alias for encryptor")
        String encryptor_alias();
    }

    private String alias;
    private String passwordFile;
    private String passwordEnvName;
    private String passwordSysPropertyName;

    /**
     * OSGi service registration of Jasypt service (PAX-JDBC uses that service interface).
     */
    private ServiceRegistration<org.jasypt.encryption.StringEncryptor> defaultStringEncryptor;

    private EnvironmentStringPBEConfig encryptorConfig;
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
        encryptor.setConfig(refreshConfig(config));

        defaultStringEncryptor = context.registerService(org.jasypt.encryption.StringEncryptor.class, encryptor, getJasyptServiceProps(config.encryptor_alias(), config.encryption_algorithm()));
    }

    /**
     * Update StringEncryptor configuration.
     *
     * @param config configuration options
     */
    @Modified
    public void update(final Config config) {
        refreshConfig(config);

        defaultStringEncryptor.setProperties(getJasyptServiceProps(config.encryptor_alias(), config.encryption_algorithm()));
    }

    /**
     * Unregister StringEncryptor service instance.
     */
    @Deactivate
    public void stop() {
        encryptor = null;
        encryptorConfig = null;
        try {
            if (defaultStringEncryptor != null) {
                defaultStringEncryptor.unregister();
            }
        } finally {
            defaultStringEncryptor = null;
        }
    }

    private SimplePBEConfig refreshConfig(final Config config) {
        alias = config.encryptor_alias();
        if (alias == null) {
            log.warn("Alias is not configured for Encryptor component.");
        }

        passwordFile = config.encryption_passwordFile();
        passwordEnvName = config.encryption_passwordEnvName();
        passwordSysPropertyName = config.encryption_passwordSysPropertyName();

        encryptorConfig = new EnvironmentStringPBEConfig();
        encryptorConfig.setAlgorithm(config.encryption_algorithm());
        if (config.encryption_password() != null) {
            encryptorConfig.setPassword(config.encryption_password());
        }

        return encryptorConfig;
    }

    private Dictionary<String, Object> getJasyptServiceProps(final String alias, final String algorithm) {
        final Dictionary<String, Object> dict = new Hashtable<>();
        dict.put(Constants.SERVICE_RANKING, Integer.MAX_VALUE);
        dict.put("algorithm", algorithm);
        if (alias != null) {
            dict.put("alias", alias);
        }

        return dict;
    }

    @Override
    public String getAlias() {
        return alias;
    }

    @Override
    public String encrypt(final String message) {
        final long startTs = System.currentTimeMillis();

        Objects.requireNonNull(encryptor, "Encryptor is not initialized yet");
        Objects.requireNonNull(encryptorConfig, "Missing encryptor configuration");

        try {
            loadPassword();
            return encryptor.encrypt(message);
        } catch (RuntimeException ex) {
            encryptionErrors.incrementAndGet();
            throw ex;
        } finally {
            cleanPassword();

            final Long endTs = System.currentTimeMillis();
            encryptionTime.addAndGet(endTs - startTs);
            encryptionCount.incrementAndGet();
        }
    }

    @Override
    public String decrypt(final String encryptedMessage) {
        final long startTs = System.currentTimeMillis();

        Objects.requireNonNull(encryptor, "Encryptor is not initialized yet");
        Objects.requireNonNull(encryptorConfig, "Missing encryptor configuration");

        try {
            loadPassword();
            return encryptor.decrypt(encryptedMessage);
        } catch (RuntimeException ex) {
            decryptionErrors.incrementAndGet();
            throw ex;
        } finally {
            cleanPassword();

            final Long endTs = System.currentTimeMillis();
            decyptionTime.addAndGet(endTs - startTs);
            decryptionCount.incrementAndGet();
        }
    }

    private void loadPassword() {
        if (passwordFile != null) {
            encryptorConfig.setPasswordCharArray(loadPasswordFromFile(passwordFile));
        } else if (passwordEnvName != null) {
            encryptorConfig.setPasswordEnvName(passwordEnvName);
        } else if (passwordSysPropertyName != null) {
            encryptorConfig.setPasswordSysPropertyName(passwordSysPropertyName);
        }
    }

    private void cleanPassword() {
        if (passwordFile != null ||passwordEnvName != null || passwordSysPropertyName != null) {
            encryptorConfig.cleanPassword();
        }
    }

    /**
     * Load password from file.
     *
     * @param path file that contains password, using default charset of platform
     * @return plain text password
     */
    private static char[] loadPasswordFromFile(final String path) {
        try {
            final byte[] encoded = Files.readAllBytes(Paths.get(path));
            return Charset.forName("UTF-8").decode(ByteBuffer.wrap(encoded)).array();
        } catch (IOException ex) {
            throw new IllegalArgumentException("Unable to read password from file: " + path, ex);
        }
    }
}
