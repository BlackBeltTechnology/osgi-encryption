package hu.blackbelt.encryption.services.impl;

import hu.blackbelt.encryption.services.Digester;
import hu.blackbelt.encryption.services.metrics.OperationStats;
import lombok.extern.slf4j.Slf4j;
import org.jasypt.digest.StandardStringDigester;
import org.jasypt.digest.config.EnvironmentStringDigesterConfig;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.AttributeType;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

import java.util.Dictionary;
import java.util.Hashtable;

@Component(immediate = true, service = Digester.class, configurationPolicy = ConfigurationPolicy.REQUIRE)
@Designate(ocd = StringDigester.Config.class)
@Slf4j
public class StringDigester implements Digester, org.jasypt.digest.StringDigester {

    private hu.blackbelt.encryption.services.impl.OperationStats digestStats = new hu.blackbelt.encryption.services.impl.OperationStats();
    private hu.blackbelt.encryption.services.impl.OperationStats digestValidationStats = new hu.blackbelt.encryption.services.impl.OperationStats();

    @SuppressWarnings("checkstyle:JavadocMethod")
    @ObjectClassDefinition(name = "String digester configuration")
    public @interface Config {

        @AttributeDefinition(name = "Digest algorithm")
        String digest_algorithm();

        @AttributeDefinition(required = false, name = "Output type (base64/hexadecimal)")
        String digest_outputType();

        @AttributeDefinition(required = false, name = "Iterations", type = AttributeType.INTEGER)
        int digest_iterations();

        @AttributeDefinition(required = false, name = "Salt size", type = AttributeType.INTEGER)
        int digest_saltSize() default DEFAULT_SALT_SIZE;

        @AttributeDefinition(required = false, name = "Alias for digester")
        String digester_alias();

        @AttributeDefinition(required = false, name = "Digester provider name")
        String digester_provider();
    }

    @lombok.Setter
    private String alias;

    @lombok.Setter
    private String algorithm;

    @lombok.Setter
    private String outputType;

    @lombok.Setter
    private int iterations;

    public static final int DEFAULT_SALT_SIZE = -1;

    @lombok.Setter
    private int saltSize = DEFAULT_SALT_SIZE;

    @lombok.Setter
    private String providerName;

    /**
     * OSGi service registration of Jasypt service (PAX-JDBC uses that service interface).
     */
    private ServiceRegistration<org.jasypt.digest.StringDigester> defaultStringDigester;

    private ServiceRegistration<OperationStats> digestStatsReg;
    private ServiceRegistration<OperationStats> digestValidationStatsReg;

    private transient org.jasypt.digest.StringDigester digester;

    /**
     * Register StringDigester service instance.
     *
     * @param cc     component context
     * @param config configuration options
     */
    @Activate
    void start(final ComponentContext cc, final StringDigester.Config config) {
        final Dictionary<String, Object> digestProps = new Hashtable<>();
        digestProps.put("alias", config.digester_alias());
        digestProps.put("type", OperationStats.Type.DIGEST);
        digestStatsReg = cc.getBundleContext().registerService(OperationStats.class, digestStats, digestProps);

        final Dictionary<String, Object> digestValidationProps = new Hashtable<>();
        digestValidationProps.put("alias", config.digest_algorithm());
        digestValidationProps.put("type", OperationStats.Type.VALIDATE_DIGEST);
        digestValidationStatsReg = cc.getBundleContext().registerService(OperationStats.class, digestValidationStats, digestValidationProps);

        refreshConfig(config);
        defaultStringDigester = cc.getBundleContext().registerService(org.jasypt.digest.StringDigester.class, this, getJasyptServiceProps(config.digester_alias(), config.digest_algorithm()));
    }

    /**
     * Update StringDigester configuration.
     *
     * @param config configuration options
     */
    @Modified
    void update(final StringDigester.Config config) {
        refreshConfig(config);
        defaultStringDigester.setProperties(getJasyptServiceProps(config.digester_alias(), config.digest_algorithm()));
        digester = null;
    }

    /**
     * Unregister StringDigester service instance.
     */
    @Deactivate
    void stop() {
        try {
            if (defaultStringDigester != null) {
                defaultStringDigester.unregister();
            }

            if (digestStatsReg != null) {
                digestStatsReg.unregister();
            }

            if (digestValidationStatsReg != null) {
                digestValidationStatsReg.unregister();
            }
        } finally {
            defaultStringDigester = null;
            digestStatsReg = null;
            digestValidationStatsReg = null;
            digester = null;
        }
    }

    private void refreshConfig(final StringDigester.Config config) {
        alias = config.digester_alias();
        if (alias == null) {
            log.warn("Alias is not configured for Digester component.");
        }

        algorithm = config.digest_algorithm();
        providerName = config.digester_provider();
        outputType = config.digest_outputType();
        iterations = config.digest_iterations();
        saltSize = config.digest_saltSize();
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

    private org.jasypt.digest.StringDigester getDigester() {
        if (digester == null) {
            final EnvironmentStringDigesterConfig digesterConfig = new EnvironmentStringDigesterConfig();
            digesterConfig.setAlgorithm(algorithm);
            if (providerName != null) {
                digesterConfig.setProviderName(providerName);
            }
            if (outputType != null) {
                digesterConfig.setStringOutputType(outputType);
            }
            if (iterations > 0) {
                digesterConfig.setIterations(iterations);
            }
            if (saltSize >= 0) {
                digesterConfig.setSaltSizeBytes(saltSize);
            }

            final StandardStringDigester digester = new StandardStringDigester();
            digester.setConfig(digesterConfig);
            this.digester = digester;
        }

        return digester;
    }

    @Override
    public String digest(final String data) {
        final long startTs = System.currentTimeMillis();

        try {
            return getDigester().digest(data);
        } catch (RuntimeException ex) {
            digestStats.incrementErrors();
            throw ex;
        } finally {
            final Long endTs = System.currentTimeMillis();
            digestStats.setProcessingTime(endTs - startTs);
        }
    }

    @Override
    public boolean matches(final String data, final String digest) {
        final long startTs = System.currentTimeMillis();

        try {
            return getDigester().matches(data, digest);
        } catch (RuntimeException ex) {
            digestValidationStats.incrementErrors();
            throw ex;
        } finally {
            final Long endTs = System.currentTimeMillis();
            digestValidationStats.setProcessingTime(endTs - startTs);
        }
    }
}
