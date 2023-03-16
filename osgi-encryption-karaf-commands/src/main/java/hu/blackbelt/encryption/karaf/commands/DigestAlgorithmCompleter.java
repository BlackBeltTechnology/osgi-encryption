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

import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.api.console.CommandLine;
import org.apache.karaf.shell.api.console.Completer;
import org.apache.karaf.shell.api.console.Session;
import org.apache.karaf.shell.support.completers.StringsCompleter;
import org.jasypt.registry.AlgorithmRegistry;

import java.util.List;

/**
 * Get digest algorithms supported by Jasypt.
 */
@Service
public class DigestAlgorithmCompleter implements Completer {

    @Override
    public int complete(final Session session, final CommandLine commandLine, final List<String> candidates) {
        final StringsCompleter delegate = new StringsCompleter();
        for (final Object algorithm : AlgorithmRegistry.getAllDigestAlgorithms()) {
            delegate.getStrings().add(algorithm.toString());
        }
        return delegate.complete(session, commandLine, candidates);
    }
}
