package hu.blackbelt.encryption.services;

public interface ConfigDecryptor {

    /**
     * Decrypt an configuration value.
     *
     * @param encryptedValue encrypted configuration value
     * @return plain text configuration value
     */
    String decrypt(String encryptedValue);

    /**
     * Check if a configuration value is encrypted or not.
     *
     * @param value configuration value
     * @return <code>true</code> if value is encrypted
     */
    boolean isEncrypted(String value);
}
