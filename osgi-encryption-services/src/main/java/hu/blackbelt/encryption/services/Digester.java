package hu.blackbelt.encryption.services;

/**
 * Common interface for all digesters which receive a String message and return a String digest.
 */
public interface Digester {

    /**
     * Return alias of digester.
     *
     * @return alias
     */
    String getAlias();

    /**
     * Create a digest of the input message.
     *
     * @param data the message to be digested
     * @return the digest
     */
    String digest(String data);


    /**
     * Check whether a message matches a digest, managing aspects like
     * salt, hashing iterations, etc. (if applicable).
     *
     * @param data the message to check
     * @param digest the digest to check
     * @return TRUE if the message matches the digest, FALSE if not.
     */
    boolean matches(String data, String digest);
}
