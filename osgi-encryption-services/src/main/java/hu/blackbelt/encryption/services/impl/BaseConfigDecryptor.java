package hu.blackbelt.encryption.services.impl;

import hu.blackbelt.encryption.services.ConfigDecryptor;
import hu.blackbelt.encryption.services.Encryptor;
import lombok.extern.slf4j.Slf4j;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public abstract class BaseConfigDecryptor implements ConfigDecryptor {

    private static final String FN_NAME = "ENC";
    private static final Pattern PATTERN = Pattern.compile("^" + FN_NAME + "\\((.*)\\)$");
    private static final Pattern PATTERN_WITH_ALIAS = Pattern.compile("^" + FN_NAME + "\\((.*)\\s*,\\s*(.*)\\)$");

    @Override
    public String decrypt(final String encryptedMessage) {
        if (encryptedMessage == null){
            return null;
        }

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
                if (log.isDebugEnabled()) {
                    log.debug("Configuration is not encrypted, using plain text value");
                }

                // not encrypted, return original value
                return encryptedMessage;
            }
        }

        final Encryptor encryptor = getEncryptor(alias);

        // return original value is encryptor not found
        return encryptor != null ? encryptor.decrypt(encrypted) : encryptedMessage;
    }

    protected abstract Encryptor getEncryptor(String alias);

    @Override
    public boolean isEncrypted(final String value) {
        return value != null ? PATTERN_WITH_ALIAS.matcher(value).matches() || PATTERN.matcher(value).matches() : false;
    }
}
