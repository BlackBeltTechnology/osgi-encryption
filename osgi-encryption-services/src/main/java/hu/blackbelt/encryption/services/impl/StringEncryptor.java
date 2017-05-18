package hu.blackbelt.encryption.services.impl;

import hu.blackbelt.encryption.services.Encryptor;
import hu.blackbelt.encryption.services.internal.FileWatcher;
import hu.blackbelt.encryption.services.metrics.OperationStats;
import lombok.extern.slf4j.Slf4j;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.EnvironmentStringPBEConfig;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.AttributeType;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Dictionary;
import java.util.Hashtable;

@Component(immediate = true, service = Encryptor.class, configurationPolicy = ConfigurationPolicy.REQUIRE)
@Designate(ocd = StringEncryptor.Config.class)
@Slf4j
public class StringEncryptor implements Encryptor, org.jasypt.encryption.StringEncryptor {

    @SuppressWarnings("checkstyle:JavadocMethod")
    @ObjectClassDefinition(name = "String encryptor configuration")
    public @interface Config {

        @AttributeDefinition(name = "Encryption algorithm")
        String encryption_algorithm();

        @AttributeDefinition(required = false, name = "Output type (base64/hexadecimal)")
        String enrcyption_outputType();

        @AttributeDefinition(required = false, name = "Key obtention iterations", type = AttributeType.INTEGER)
        int enrcyption_keyObtentionIterations();

        @AttributeDefinition(required = false, name = "Password for encryption", type = AttributeType.PASSWORD)
        String encryption_password();

        @AttributeDefinition(required = false, name = "Password file for encryption")
        String encryption_passwordFile();

        @AttributeDefinition(required = false, name = "Environment variable holding password file for encryption")
        String encryption_passwordFileEnvName();

        @AttributeDefinition(required = false, name = "JVM argument holding password file path for encryption")
        String encryption_passwordFileSysPropertyName();

        @AttributeDefinition(required = false, name = "Environment variable holding password for encryption")
        String encryption_passwordEnvName();

        @AttributeDefinition(required = false, name = "JVM argument holding password for encryption")
        String encryption_passwordSysPropertyName();

        @AttributeDefinition(required = false, name = "Alias for encryptor")
        String encryptor_alias();

        @AttributeDefinition(required = false, name = "Encryptor provider name")
        String encryptor_provider();

        @AttributeDefinition(required = false, name = "Enable password file watcher", description = "Enable password file watcher and trigger configuration reload on change", type = AttributeType.BOOLEAN)
        boolean encryptor_enablePasswordFileWatcher() default DEFAULT_ENABLE_PASSWORD_FILE_WATCHER;
    }

    @lombok.Setter
    private String alias;

    @lombok.Setter
    private String algorithm;

    @lombok.Setter
    private String outputType;

    @lombok.Setter
    private int keyObtentionIterations;

    private char[] password;

    @lombok.Setter
    private String passwordFile;

    @lombok.Setter
    private String passwordFileEnvName;

    @lombok.Setter
    private String passwordFileSysPropertyName;

    @lombok.Setter
    private String passwordEnvName;

    @lombok.Setter
    private String passwordSysPropertyName;

    @lombok.Setter
    private String providerName;

    private FileWatcher fileWatcher;

    private ComponentContext cc;

    private hu.blackbelt.encryption.services.impl.OperationStats encryptionStats = new hu.blackbelt.encryption.services.impl.OperationStats();
    private hu.blackbelt.encryption.services.impl.OperationStats decryptionStats = new hu.blackbelt.encryption.services.impl.OperationStats();

    @Reference(policyOption = ReferencePolicyOption.GREEDY)
    private ConfigurationAdmin configAdmin;

    public static final boolean DEFAULT_ENABLE_PASSWORD_FILE_WATCHER = true;
    private volatile boolean enablePasswordFileWatcher;

    /**
     * OSGi service registration of Jasypt service (PAX-JDBC uses that service interface).
     */
    private ServiceRegistration<org.jasypt.encryption.StringEncryptor> defaultStringEncryptor;

    private ServiceRegistration<OperationStats> encryptionStatsReg;
    private ServiceRegistration<OperationStats> decryptionStatsReg;

    private org.jasypt.encryption.StringEncryptor encryptor;

    /**
     * Register StringEncryptor service instance.
     *
     * @param cc     component context
     * @param config configuration options
     */
    @Activate
    void start(final ComponentContext cc, final Config config) {
        this.cc = cc;

        final Dictionary<String, Object> encryptionProps = new Hashtable<>();
        encryptionProps.put("alias", config.encryptor_alias());
        encryptionProps.put("type", OperationStats.Type.ENCRYPTION);
        encryptionStatsReg = cc.getBundleContext().registerService(OperationStats.class, encryptionStats, encryptionProps);

        final Dictionary<String, Object> decryptionProps = new Hashtable<>();
        decryptionProps.put("alias", config.encryptor_alias());
        decryptionProps.put("type", OperationStats.Type.DECRYPTION);
        decryptionStatsReg = cc.getBundleContext().registerService(OperationStats.class, decryptionStats, decryptionProps);

        refreshConfig(config);
        defaultStringEncryptor = cc.getBundleContext().registerService(org.jasypt.encryption.StringEncryptor.class, this, getJasyptServiceProps(config.encryptor_alias(), config.encryption_algorithm()));
    }

    /**
     * Update StringEncryptor configuration.
     *
     * @param config configuration options
     */
    @Modified
    void update(final Config config) {
        refreshConfig(config);
        defaultStringEncryptor.setProperties(getJasyptServiceProps(config.encryptor_alias(), config.encryption_algorithm()));
        encryptor = null;
    }

    /**
     * Unregister StringEncryptor service instance.
     */
    @Deactivate
    void stop() {
        try {
            if (defaultStringEncryptor != null) {
                defaultStringEncryptor.unregister();
            }

            if (encryptionStatsReg != null) {
                encryptionStatsReg.unregister();
            }
            if (decryptionStatsReg != null) {
                decryptionStatsReg.unregister();
            }

            if (fileWatcher != null) {
                fileWatcher.stop();
            }
        } finally {
            defaultStringEncryptor = null;
            fileWatcher = null;
            encryptionStatsReg = null;
            decryptionStatsReg = null;
            encryptor = null;
        }
    }

    private void refreshConfig(final Config config) {
        alias = config.encryptor_alias();
        if (alias == null) {
            log.warn("Alias is not configured for Encryptor component, cannot used for decrypting configuration parameters.");
        }

        enablePasswordFileWatcher = config.encryptor_enablePasswordFileWatcher();
        synchronized (this) {
            if (fileWatcher != null && !enablePasswordFileWatcher) {
                fileWatcher.stop();
                fileWatcher = null;
            }
        }

        password = config.encryption_password() != null ? config.encryption_password().toCharArray() : null;
        passwordFile = config.encryption_passwordFile();
        passwordFileEnvName = config.encryption_passwordFileEnvName();
        passwordFileSysPropertyName = config.encryption_passwordFileSysPropertyName();
        passwordEnvName = config.encryption_passwordEnvName();
        passwordSysPropertyName = config.encryption_passwordSysPropertyName();

        algorithm = config.encryption_algorithm();
        providerName = config.encryptor_provider();
        outputType = config.enrcyption_outputType();
        keyObtentionIterations = config.enrcyption_keyObtentionIterations();
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

    private org.jasypt.encryption.StringEncryptor getEncryptor() {
        if (encryptor == null) {
            final EnvironmentStringPBEConfig encryptorConfig = new EnvironmentStringPBEConfig();
            encryptorConfig.setAlgorithm(algorithm);
            if (providerName != null) {
                encryptorConfig.setProviderName(providerName);
            }
            if (outputType != null) {
                encryptorConfig.setStringOutputType(outputType);
            }
            if (keyObtentionIterations > 0) {
                encryptorConfig.setKeyObtentionIterations(keyObtentionIterations);
            }

            if (passwordFile == null && passwordFileEnvName != null) {
                passwordFile = System.getenv(passwordFileEnvName);
            } else if (passwordFile == null && passwordFileSysPropertyName != null) {
                passwordFile = System.getProperty(passwordFileSysPropertyName);
            }

            if (password != null) {
                encryptorConfig.setPasswordCharArray(password);
            } else if (passwordFile != null) {
                encryptorConfig.setPasswordCharArray(loadPasswordFromFile(passwordFile));
                if (enablePasswordFileWatcher) {
                    synchronized (this) {
                        if (fileWatcher == null) {
                            fileWatcher = new PasswordFileWatcher(passwordFile);
                            final Thread thread = new Thread(fileWatcher, passwordFile + " watcher");
                            thread.start();
                        }
                    }
                }
            } else if (passwordEnvName != null) {
                encryptorConfig.setPasswordEnvName(passwordEnvName);
            } else if (passwordSysPropertyName != null) {
                encryptorConfig.setPasswordSysPropertyName(passwordSysPropertyName);
            }

            final StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
            encryptor.setConfig(encryptorConfig);
            this.encryptor = encryptor;
        }

        return encryptor;
    }

    private void passwordFileContentChanged() {
        if (log.isDebugEnabled()) {
            log.debug("Password file updated for StringEncryptor '" + alias + "'");
        }

        final ServiceReference<Encryptor> sr = (ServiceReference<Encryptor>) cc.getServiceReference();
        if (sr != null) {
            final String pid = (String) sr.getProperty(Constants.SERVICE_PID);
            try {
                final Configuration config = configAdmin.getConfiguration(pid);
                final Dictionary dict = config.getProperties();
                dict.put("lastModified", System.currentTimeMillis());
                config.update(dict);
                if (log.isTraceEnabled()) {
                    log.trace("Updated configuration for PID: " + pid);
                }
            } catch (IOException ex) {
                log.error("Unable to get configuration", ex);
            }
        }
    }

    @Override
    public String encrypt(final String message) {
        final long startTs = System.currentTimeMillis();

        try {
            return getEncryptor().encrypt(message);
        } catch (RuntimeException ex) {
            encryptionStats.incrementErrors();
            throw ex;
        } finally {
            final Long endTs = System.currentTimeMillis();
            encryptionStats.setProcessingTime(endTs - startTs);
        }
    }

    @Override
    public String decrypt(final String encryptedMessage) {
        final long startTs = System.currentTimeMillis();

        try {
            return getEncryptor().decrypt(encryptedMessage);
        } catch (RuntimeException ex) {
            decryptionStats.incrementErrors();
            throw ex;
        } finally {
            final Long endTs = System.currentTimeMillis();
            decryptionStats.setProcessingTime(endTs - startTs);
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

    private class PasswordFileWatcher extends FileWatcher {

        PasswordFileWatcher(final String path) {
            super(path);
        }

        @Override
        protected void onCreate(final Path path) {
            super.onCreate(path);
            passwordFileContentChanged();
        }

        @Override
        protected void onModify(Path path) {
            super.onModify(path);
            passwordFileContentChanged();
        }

        @Override
        protected void onDelete(Path path) {
            super.onDelete(path);
            passwordFileContentChanged();
        }
    }
}
