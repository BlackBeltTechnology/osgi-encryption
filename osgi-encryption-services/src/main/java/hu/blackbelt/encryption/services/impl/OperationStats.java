package hu.blackbelt.encryption.services.impl;

/*-
 * #%L
 * OSGi encryption services
 * %%
 * Copyright (C) 2018 - 2023 BlackBelt Technology
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

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
