package hu.blackbelt.encryption.services.impl;

import hu.blackbelt.encryption.services.Encryptor;
import lombok.extern.slf4j.Slf4j;
import org.osgi.service.component.annotations.*;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component(immediate = true)
@Slf4j
public class ConfigDecryptor implements hu.blackbelt.encryption.services.ConfigDecryptor {

    private static final String FN_NAME = "ENC";
    private static final Pattern PATTERN_WITHOUT_ALIAS = Pattern.compile("^" + FN_NAME + "\\((.*)\\)$");
    private static final Pattern PATTERN_WITH_ALIAS = Pattern.compile("^" + FN_NAME + "\\((.*)\\s*,\\s*(.*)\\)$");

    private static final String DEFAULT_ENCRYPTOR_ALIAS = "default";

    private Map<String, Encryptor> encryptors = new HashMap<>();

    @Reference(policyOption = ReferencePolicyOption.GREEDY, unbind = "unregisterEncryptor", cardinality = ReferenceCardinality.AT_LEAST_ONE)
    void registerEncryptor(final Encryptor encryptor) {
        encryptors.put(encryptor.getAlias(), encryptor);
    }

    void unregisterEncryptor(final Encryptor encryptor) {
        encryptors.remove(encryptor.getAlias());
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
            final Matcher mWithoutAias = PATTERN_WITHOUT_ALIAS.matcher(encryptedMessage);
            if (mWithoutAias.matches()) {
                encrypted = mWithoutAias.group(1);
                alias = DEFAULT_ENCRYPTOR_ALIAS;
            } else {
                throw new IllegalArgumentException("Invalid encrypted message format");
            }
        }

        final Encryptor enc = encryptors.get(alias);
        if (enc == null) {
            log.warn("Registered encryptor instances: " + encryptors.keySet());
            throw new IllegalStateException("Encryptor with alias '" + alias + "' not found");
        }
        final String decrypted = enc.decrypt(encrypted);

        return decrypted;
    }

    @Override
    public boolean isEncrypted(final String value) {
        return value != null ? PATTERN_WITHOUT_ALIAS.matcher(value).matches() : false;
    }
}
