package hu.blackbelt.encryption.karaf.commands;

/*-
 * #%L
 * OSGi encryption Karaf commands
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

import org.apache.karaf.shell.api.action.*;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.EnvironmentStringPBEConfig;

/**
 * Apache Karaf command to encrypt a string.
 */
@Command(scope = "jasypt", name = "encrypt", description = "Encrypt String value.")
@Service
public class Encrypt implements Action {

    @Argument(index = 0, name = "text", description = "Text to encrypt", required = true, multiValued = false)
    private String text;

    @Option(name = "--algorithm", description = "Algorithm of encryption", required = true, multiValued = false)
    @Completion(PBEAlgorithmCompleter.class)
    private String algorithm;

    @Option(name = "--provider", description = "Provider name", required = false, multiValued = false)
    private String providerName;

    @Option(name = "--password", description = "Password for encryption", required = false, multiValued = false)
    private String password;

    @Option(name = "--password-env", description = "Password environment variable for encryption", required = false, multiValued = false)
    private String passwordEnvName;

    @Option(name = "--password-prop", description = "Password system property for encryption", required = false, multiValued = false)
    private String passwordSysPropertyName;

    @Option(name = "--outputType", description = "Output type", required = false, multiValued = false)
    @Completion(OutputTypeCompleter.class)
    private String outputType = OutputTypeCompleter.BASE64;

    @Override
    public Object execute() {
        final StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        final EnvironmentStringPBEConfig config = new EnvironmentStringPBEConfig();
        config.setAlgorithm(algorithm);
        if (providerName != null) {
            config.setProviderName(providerName);
        }
        if (password != null) {
            config.setPassword(password);
        } else if (passwordEnvName != null) {
            config.setPasswordEnvName(passwordEnvName);
        } else if (passwordSysPropertyName != null) {
            config.setPasswordSysPropertyName(passwordSysPropertyName);
        }
        config.setStringOutputType(outputType);
        encryptor.setConfig(config);

        System.out.println("Encrypted value is: " + encryptor.encrypt(text));

        return null;
    }
}
