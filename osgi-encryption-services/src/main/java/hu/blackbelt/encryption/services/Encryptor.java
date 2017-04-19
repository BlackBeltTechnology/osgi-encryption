package hu.blackbelt.encryption.services;

/**
 * Common interface for all Encryptors which receive a String message and return a String result.
 */
public interface Encryptor {

    /**
     * Encrypt the input message
     *
     * @param message the message to be encrypted
     * @return the result of encryption
     */
    String encrypt(String message);


    /**
     * Decrypt an encrypted message
     *
     * @param encryptedMessage the encrypted message to be decrypted
     * @return the result of decryption
     */
    String decrypt(String encryptedMessage);
}
