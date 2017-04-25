package hu.blackbelt.encryption.services.impl;

import lombok.extern.slf4j.Slf4j;
import org.osgi.framework.BundleContext;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.annotations.*;

import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component(immediate = true)
@Slf4j
public class ConfigDecryptor implements hu.blackbelt.encryption.services.ConfigDecryptor {

    private static final String FN_NAME = "ENC";
    private static final Pattern PATTERN = Pattern.compile("^" + FN_NAME + "\\((.*)\\)$");
    private static final Pattern PATTERN_WITH_ALIAS = Pattern.compile("^" + FN_NAME + "\\((.*)\\s*,\\s*(.*)\\)$");

    private BundleContext context;

    @Activate
    void start(final BundleContext context) {
        this.context = context;
    }

    void stop() {
        context = null;
    }

    @Override
    public String decrypt(final String encryptedMessage) {
        final Matcher mWithAias = PATTERN_WITH_ALIAS.matcher(encryptedMessage);
        final String encrypted;
        final String alias;
        if (mWithAias.matches()) {
            encrypted = mWithAias.group(1);
            alias = mWithAias.group(2);
        } else {
            final Matcher mWithoutAias = PATTERN.matcher(encryptedMessage);
            if (mWithoutAias.matches()) {
                encrypted = mWithoutAias.group(1);
                alias = null;
            } else {
                throw new IllegalArgumentException("Invalid encrypted message format");
            }
        }

        try {
            final String filter = alias != null ? "(encryptor.alias=" + alias + ")" : null;
            final Collection<ServiceReference<hu.blackbelt.encryption.services.Encryptor>> srs = context.getServiceReferences(hu.blackbelt.encryption.services.Encryptor.class, filter);
            if (srs.isEmpty()) {
                throw new IllegalStateException("Encryptor with alias '" + alias + "' not found");
            }
            final hu.blackbelt.encryption.services.Encryptor encryptor = context.getService(srs.iterator().next());

            if (srs.size() > 1) {
                log.warn("More than 1 encryptors found for alias: " + alias + ", decryption is nondeterministic (used alias: " + encryptor.getAlias() + ")");
            }

            return encryptor.decrypt(encrypted);
        } catch (InvalidSyntaxException ex) {
            throw new IllegalStateException("Invalid encryptor alias: " + alias, ex);
        } catch (RuntimeException ex) {
            log.error("Unable to decrypt data, alias = " + alias, ex);

            // return original value
            return encryptedMessage;
        }
    }

    @Override
    public boolean isEncrypted(final String value) {
        return value != null ? PATTERN.matcher(value).matches() : false;
    }
}
