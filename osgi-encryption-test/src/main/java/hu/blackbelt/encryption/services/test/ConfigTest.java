package hu.blackbelt.encryption.services.test;

import hu.blackbelt.encryption.services.Encryptor;
import lombok.extern.slf4j.Slf4j;
import org.osgi.service.component.annotations.*;

import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;

@Component(immediate = true, service = ConfigTest.class)
@Slf4j
public class ConfigTest {

    @Reference(policyOption = ReferencePolicyOption.GREEDY, policy = ReferencePolicy.DYNAMIC)
    private volatile hu.blackbelt.encryption.services.ConfigDecryptor configEncryptor;

    private Map<String, Object> originalProperties = new TreeMap<>();

    @Reference(name = "defaultEncryptor", bind = "setEncryptor", updated = "setEncryptor", unbind = "unsetEncryptor", policyOption = ReferencePolicyOption.GREEDY, cardinality = ReferenceCardinality.AT_LEAST_ONE, policy = ReferencePolicy.DYNAMIC, target = "(encryptor.alias=default)", fieldOption = FieldOption.UPDATE)
    private volatile Collection<Encryptor> defaultEncryptor = null;

    @Reference(name = "testEncryptor", bind = "setEncryptor", updated = "setEncryptor", unbind = "unsetEncryptor", policyOption = ReferencePolicyOption.GREEDY, cardinality = ReferenceCardinality.AT_LEAST_ONE, policy = ReferencePolicy.DYNAMIC, target = "(encryptor.alias=test)", fieldOption = FieldOption.UPDATE)
    private volatile Collection<Encryptor> testEncryptor = null;


    @Activate
    void start(final Map<String, Object> props) {
        originalProperties.putAll(props);

        updateConfig();
    }

    void stop() {
        originalProperties.clear();
    }

    private void updateConfig() {
        log.info("Updating configuration");

        for (final Map.Entry<String, Object> me : originalProperties.entrySet()) {
            final String key = me.getKey();
            final String value = me.getValue() != null ? me.getValue().toString() : null;

            String decrypted = value;
            if (configEncryptor.isEncrypted(value)) {
                decrypted = configEncryptor.decrypt(value);
            }

            log.debug("KEY: " + key + "; VALUE: " + decrypted);
        }
    }

    void setEncryptor(final Encryptor encryptor, final Map<String, Object> props) {
        log.info("BIND/UPDATE default encryptor");
        updateConfig();
    }

    void unsetEncryptor(final Encryptor encryptor) {
        log.info("UNBIND default encryptor");
    }
}
