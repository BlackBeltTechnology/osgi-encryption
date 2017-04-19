package hu.blackbelt.encryption.karaf.commands;

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
