package hu.blackbelt.encryption.services.impl;

import hu.blackbelt.encryption.services.Digester;
import hu.blackbelt.encryption.services.metrics.OperationStats;
import lombok.extern.slf4j.Slf4j;
import org.jasypt.digest.StandardStringDigester;
import org.jasypt.digest.config.DigesterConfig;
import org.jasypt.digest.config.EnvironmentStringDigesterConfig;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

import java.util.Dictionary;
import java.util.Hashtable;
import java.util.Objects;

@Component(immediate = true, configurationPolicy = ConfigurationPolicy.REQUIRE)
@Designate(ocd = StringDigester.Config.class)
@Slf4j
public class StringDigester implements Digester {

    private hu.blackbelt.encryption.services.impl.OperationStats digestStats = new hu.blackbelt.encryption.services.impl.OperationStats();
    private hu.blackbelt.encryption.services.impl.OperationStats digestValidationStats = new hu.blackbelt.encryption.services.impl.OperationStats();

    @SuppressWarnings("checkstyle:JavadocMethod")
    @ObjectClassDefinition(name = "String digester configuration")
    public @interface Config {

        @AttributeDefinition(name = "Digest algorithm")
        String digest_algorithm();

        @AttributeDefinition(required = false, name = "Alias for digester")
        String digester_alias();
    }

    private String alias;

    /**
     * OSGi service registration of Jasypt service (PAX-JDBC uses that service interface).
     */
    private ServiceRegistration<org.jasypt.digest.StringDigester> defaultStringDigester;

    private ServiceRegistration<OperationStats> digestStatsReg;
    private ServiceRegistration<OperationStats> digestValidationStatsReg;

    private EnvironmentStringDigesterConfig digesterConfig;
    private StandardStringDigester digester;

    /**
     * Register StringDigester service instance.
     *
     * @param cc     component context
     * @param config configuration options
     */
    @Activate
    void start(final ComponentContext cc, final StringDigester.Config config) {
        digester = new StandardStringDigester();
        digester.setConfig(refreshConfig(config));

        final Dictionary<String, Object> digestProps = new Hashtable<>();
        digestProps.put("alias", config.digester_alias());
        digestProps.put("type", OperationStats.Type.DIGEST);
        digestStatsReg = cc.getBundleContext().registerService(OperationStats.class, digestStats, digestProps);

        final Dictionary<String, Object> digestValidationProps = new Hashtable<>();
        digestValidationProps.put("alias", config.digest_algorithm());
        digestValidationProps.put("type", OperationStats.Type.VALIDATE_DIGEST);
        digestValidationStatsReg = cc.getBundleContext().registerService(OperationStats.class, digestValidationStats, digestValidationProps);

        defaultStringDigester = cc.getBundleContext().registerService(org.jasypt.digest.StringDigester.class, digester, getJasyptServiceProps(config.digester_alias(), config.digest_algorithm()));
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
    }

    /**
     * Unregister StringDigester service instance.
     */
    @Deactivate
    void stop() {
        digester = null;
        digesterConfig = null;
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
        }
    }

    private DigesterConfig refreshConfig(final StringDigester.Config config) {
        alias = config.digester_alias();
        if (alias == null) {
            log.warn("Alias is not configured for Digester component.");
        }

        digesterConfig = new EnvironmentStringDigesterConfig();
        digesterConfig.setAlgorithm(config.digest_algorithm());

        return digesterConfig;
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
    public String digest(final String data) {
        final long startTs = System.currentTimeMillis();

        Objects.requireNonNull(digester, "Digester is not initialized yet");
        Objects.requireNonNull(digesterConfig, "Missing digester configuration");

        try {
            return digester.digest(data);
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

        Objects.requireNonNull(digester, "Digester is not initialized yet");
        Objects.requireNonNull(digesterConfig, "Missing digester configuration");

        try {
            return digester.matches(data, digest);
        } catch (RuntimeException ex) {
            digestValidationStats.incrementErrors();
            throw ex;
        } finally {
            final Long endTs = System.currentTimeMillis();
            digestValidationStats.setProcessingTime(endTs - startTs);
        }
    }
}
