package hu.blackbelt.encryption.services;

/**
 * Common interface for all Encryptors which receive a String message and return a String result.
 */
public interface Encryptor {

    /**
     * Return alias of encryptor.
     *
     * @return alias
     */
    String getAlias();

    /**
     * Encrypt the input message
     *
     * @param data the message to be encrypted
     * @return the result of encryption
     */
    String encrypt(String data);


    /**
     * Decrypt an encrypted message
     *
     * @param encryptedMessage the encrypted message to be decrypted
     * @return the result of decryption
     */
    String decrypt(String encryptedMessage);
}
