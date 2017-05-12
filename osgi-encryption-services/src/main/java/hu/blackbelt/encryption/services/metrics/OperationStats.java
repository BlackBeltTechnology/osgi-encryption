package hu.blackbelt.encryption.services.metrics;

public interface OperationStats {

    enum Type {
        ENCRYPTION, DECRYPTION, DIGEST, VALIDATE_DIGEST
    }

    long getTotalProcessingTime();

    int getRequestCounter();

    int getErrorCounter();
}
