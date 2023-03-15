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
