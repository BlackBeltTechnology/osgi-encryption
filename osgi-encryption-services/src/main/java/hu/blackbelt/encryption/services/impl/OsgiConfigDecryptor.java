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

import hu.blackbelt.encryption.services.ConfigDecryptor;
import hu.blackbelt.encryption.services.Encryptor;
import lombok.extern.slf4j.Slf4j;
import org.osgi.framework.BundleContext;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.annotations.*;

import java.text.MessageFormat;
import java.util.Collection;

@Component(immediate = true, service = ConfigDecryptor.class)
@Slf4j
public class OsgiConfigDecryptor extends BaseConfigDecryptor {

    private BundleContext context;

    private static final MessageFormat FILTER = new MessageFormat("(encryptor.alias={0})");

    @Activate
    void start(final BundleContext context) {
        this.context = context;
    }

    @Deactivate
    void stop() {
        context = null;
    }

    protected Encryptor getEncryptor(final String alias) {
        try {
            final String filter = alias != null ? FILTER.format(new Object[] {alias}) : null;
            final Collection<ServiceReference<Encryptor>> srs = context.getServiceReferences(Encryptor.class, filter);
            if (srs.isEmpty()) {
                throw new IllegalStateException("Encryptor with alias '" + alias + "' not found");
            }
            final Encryptor encryptor = context.getService(srs.iterator().next());

            if (srs.size() > 1) {
                log.warn("More than 1 encryptors found for alias: " + alias + ", decryption is nondeterministic (used alias: " + encryptor.getAlias() + ")");
            }

            return encryptor;
        } catch (InvalidSyntaxException ex) {
            throw new IllegalStateException("Invalid encryptor alias: " + alias, ex);
        } catch (RuntimeException ex) {
            log.error("Unable to decrypt data, alias = " + alias, ex);
            return null;
        }
    }
}
