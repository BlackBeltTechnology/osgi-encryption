package hu.blackbelt.encryption.services.impl;

import lombok.extern.slf4j.Slf4j;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleEvent;
import org.osgi.util.tracker.BundleTracker;

import java.security.Provider;
import java.security.Security;
import java.util.*;

@Slf4j
public class Activator implements BundleActivator {

    private Collection<String> PROVIDERS = Arrays.asList("org.bouncycastle.jce.provider.BouncyCastleProvider");

    private Map<Bundle, Collection<Provider>> registeredProviders = new HashMap<>();

    private BundleTracker tracker;

    @Override
    public void start(final BundleContext context) {
        tracker = new Tracker(context);
        tracker.open();
    }

    @Override
    public void stop(final BundleContext context) {
        try {
            if (tracker != null) {
                tracker.close();
            }
        } finally {
            tracker = null;
        }
    }

    private class Tracker extends BundleTracker {

        public Tracker(final BundleContext context) {
            super(context, Bundle.ACTIVE | Bundle.RESOLVED, null);
        }

        @Override
        public final Object addingBundle(final Bundle bundle, final BundleEvent event) {
            fireStatusChange(bundle, event);

            return super.addingBundle(bundle, event);
        }

        @SuppressWarnings("PMD.CyclomaticComplexity")
        private void fireStatusChange(final Bundle bundle, final BundleEvent event) {
            if (bundle == null) {
                return;
            }

            if (bundle.getState() == Bundle.ACTIVE && (event == null || event.getType() == BundleEvent.STARTED)) {
                final Collection<Provider> providers = new LinkedList<>();
                for (final String providerClassName : PROVIDERS) {
                    try {
                        final Class c = bundle.loadClass(providerClassName);
                        final Provider provider = (Provider) c.newInstance();

                        Security.addProvider(provider);
                        log.info("Registered security provider: " + provider.getName());
                    } catch (ClassNotFoundException ex) {
                        if (log.isTraceEnabled()) {
                            log.trace("Security provider '" + providerClassName + "' not found in activated bundle");
                        }
                    } catch (InstantiationException | IllegalAccessException ex) {
                        log.error("Unable to register security provider '" + providerClassName + "'", ex);
                    }
                }

                registeredProviders.put(bundle, providers);
            } else if (bundle.getState() != Bundle.ACTIVE && event != null) {
                final Collection<Provider> providers = registeredProviders.get(bundle);
                if (providers != null) {
                    for (final Provider provider : providers) {
                        try {
                            final String providerName = provider.getName();
                            Security.removeProvider(providerName);
                            log.info("Unregistered security provider: " + providerName);
                        } finally {
                            registeredProviders.remove(bundle);
                        }
                    }
                }
            }
        }
    }
}
