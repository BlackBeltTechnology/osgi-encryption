package hu.blackbelt.encryption.jmx;

import hu.blackbelt.encryption.services.metrics.OperationStats;

public class Stats implements StatsMBean {

    private final OperationStats stats;

    public Stats(final OperationStats stats) {
        this.stats = stats;
    }

    @Override
    public long getTotalProcessingTime() {
        return stats.getTotalProcessingTime();
    }

    @Override
    public int getRequestCounter() {
        return stats.getRequestCounter();
    }

    @Override
    public int getErrorCounter() {
        return stats.getErrorCounter();
    }
}
