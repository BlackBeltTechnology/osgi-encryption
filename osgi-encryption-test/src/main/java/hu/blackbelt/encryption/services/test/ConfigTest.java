package hu.blackbelt.encryption.services.test;

import hu.blackbelt.encryption.services.ConfigDecryptor;
import hu.blackbelt.encryption.services.Encryptor;
import lombok.extern.slf4j.Slf4j;
import org.osgi.service.component.annotations.*;

import java.util.Map;
import java.util.TreeMap;

@Component(immediate = true, service = ConfigTest.class, reference = {
        @Reference(name = "encryptor", service = Encryptor.class, bind = "setEncryptor", updated = "updateEncryptor", unbind = "unsetEncryptor", cardinality = ReferenceCardinality.AT_LEAST_ONE, policyOption = ReferencePolicyOption.GREEDY, policy = ReferencePolicy.DYNAMIC)
})
@Slf4j
public class ConfigTest {

    @Reference(policyOption = ReferencePolicyOption.GREEDY, policy = ReferencePolicy.DYNAMIC)
    private volatile ConfigDecryptor configEncryptor;

    private Map<String, Object> originalProperties = new TreeMap<>();

    @Activate
    void start(final Map<String, Object> props) {
        log.info("STARTING ConfigTest");

        originalProperties.putAll(props);

        updateConfig();
    }

    @Modified
    void update(final Map<String, Object> props) {
        log.info("UPDATING ConfigTest");

        originalProperties.clear();
        originalProperties.putAll(props);

        updateConfig();
    }

    @Deactivate
    void stop() {
        log.info("STOPPING ConfigTest");

        originalProperties.clear();
    }

    void setEncryptor(final Encryptor encryptor, final Map<String, Object> props) {
        log.info("BIND encryptor: " + encryptor.getAlias());
    }

    void updateEncryptor(final Encryptor encryptor, final Map<String, Object> props) {
        log.info("UPDATE encryptor: " + encryptor.getAlias());
        updateConfig();
    }

    void unsetEncryptor(final Encryptor encryptor) {
        log.info("UNBIND encryptor: " + encryptor.getAlias());
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
}
