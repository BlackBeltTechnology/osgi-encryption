package hu.blackbelt.encryption.metrics;

import hu.blackbelt.encryption.jmx.Stats;
import hu.blackbelt.encryption.services.metrics.OperationStats;
import lombok.extern.slf4j.Slf4j;
import org.osgi.service.component.annotations.*;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

import javax.management.*;
import java.lang.management.ManagementFactory;
import java.util.HashMap;
import java.util.Map;

@Component(immediate = true, service = JmxOperationStatsProvider.class, reference = {
        @Reference(name = "operationStats", service = OperationStats.class, policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.MULTIPLE, policyOption = ReferencePolicyOption.GREEDY, bind = "registerStats", unbind = "unregisterStats")
})
@Designate(ocd = JmxOperationStatsProvider.Config.class)
@Slf4j
public class JmxOperationStatsProvider {

    @SuppressWarnings("checkstyle:JavadocMethod")
    @ObjectClassDefinition(name = "JMX operation statistics for encryption services")
    public @interface Config {

        @AttributeDefinition(required = false, name = "JMX package name", description = "Package name and operationStats.target filter must be defined if multiple versions of encryption services are used.")
        String jmx_package() default DEFAULT_PACKAGE_NAME;
    }

    private Map<OperationStats, Map<String, Object>> mbeans = new HashMap<>();
    private MBeanServer mbs;

    public static final String DEFAULT_PACKAGE_NAME = "hu.blackbelt.encryption";
    private String packageName;

    @Activate
    void start(final Config config) {
        packageName = config.jmx_package();
        mbs = ManagementFactory.getPlatformMBeanServer();

        for (final OperationStats os : mbeans.keySet()) {
            register(os);
        }
    }

    @Deactivate
    void stop() {
        for (final OperationStats os : mbeans.keySet()) {
            unregister(os);
        }

        mbs = null;
    }

    void registerStats(final OperationStats operationStats, final Map<String, Object> props) {
        mbeans.put(operationStats, props);

        register(operationStats);
    }

    void updateStats(final OperationStats operationStats) {
        log.error("Updating properties of operation stats is not supported");
    }

    void unregisterStats(final OperationStats operationStats, final Map<String, Object> props) {
        unregister(operationStats);

        mbeans.remove(operationStats);
    }

    private ObjectName getObjectName(final Map<String, Object> props) throws MalformedObjectNameException {
        final String type = String.valueOf(props.get("type"));
        final String alias = String.valueOf(props.get("alias"));
        return new ObjectName(packageName + ":type=" + type + ",name=" + alias);
    }

    private void register(final OperationStats operationStats) {
        if (mbs != null) {
            try {
                final ObjectName name = getObjectName(mbeans.get(operationStats));
                if (log.isDebugEnabled()) {
                    log.debug("Registering JMX MBean: " + name);
                }
                mbs.registerMBean(new Stats(operationStats), name);
            } catch (MalformedObjectNameException | MBeanRegistrationException | NotCompliantMBeanException ex) {
                log.error("Unable to register JMX MBean", ex);
            } catch (InstanceAlreadyExistsException ex) {
                log.warn("JMX bean is already registered", ex);
            }
        }
    }

    private void unregister(final OperationStats operationStats) {
        if (mbs != null) {
            try {
                final ObjectName name = getObjectName(mbeans.get(operationStats));
                if (log.isDebugEnabled()) {
                    log.debug("Unregistering JMX MBean: " + name);
                }
                mbs.unregisterMBean(name);
            } catch (MalformedObjectNameException | MBeanRegistrationException ex) {
                log.error("Unable to unregister JMX MBean", ex);
            } catch (InstanceNotFoundException ex) {
                log.warn("JMX bean is not registered", ex);
            }
        }
    }
}
