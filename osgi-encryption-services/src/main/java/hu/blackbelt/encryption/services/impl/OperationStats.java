package hu.blackbelt.encryption.services.impl;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class OperationStats implements hu.blackbelt.encryption.services.metrics.OperationStats {

    private AtomicLong totalProcessingTime = new AtomicLong();

    private AtomicInteger requestCounter = new AtomicInteger();

    private AtomicInteger errorCounter = new AtomicInteger();

    @Override
    public long getTotalProcessingTime() {
        return totalProcessingTime.longValue();
    }

    @Override
    public int getRequestCounter() {
        return requestCounter.get();
    }

    @Override
    public int getErrorCounter() {
        return errorCounter.get();
    }

    void setProcessingTime(long processingTime) {
        requestCounter.incrementAndGet();
        this.totalProcessingTime.addAndGet(processingTime);
    }

    void incrementErrors() {
        errorCounter.incrementAndGet();
    }
}
