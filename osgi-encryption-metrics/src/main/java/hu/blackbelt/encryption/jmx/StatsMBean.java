package hu.blackbelt.encryption.jmx;

public interface StatsMBean {

    long getTotalProcessingTime();

    int getRequestCounter();

    int getErrorCounter();
}
