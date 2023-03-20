package hu.blackbelt.encryption.services;

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
