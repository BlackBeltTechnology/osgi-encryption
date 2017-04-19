package hu.blackbelt.encryption.services;

/**
 * Common interface for all digesters which receive a String message and return a String digest.
 */
public interface Digester {

    /**
     * Create a digest of the input message.
     *
     * @param message the message to be digested
     * @return the digest
     */
    String digest(String message);


    /**
     * Check whether a message matches a digest, managing aspects like
     * salt, hashing iterations, etc. (if applicable).
     *
     * @param message the message to check
     * @param digest the digest to check
     * @return TRUE if the message matches the digest, FALSE if not.
     */
    boolean matches(String message, String digest);
}
