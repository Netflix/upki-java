/*
 * Copyright 2026 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.netflix.security.provider;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.util.Collections;
import java.util.Objects;

import com.netflix.security.upki.RevocationDiagnostics;
import com.netflix.security.upki.UpkiConfiguration;
import com.netflix.security.upki.checker.ConfiguredChecks;
import com.netflix.security.upki.provider.DelegatingService;
import com.netflix.security.upki.provider.ProviderConfiguration;

/**
 * Offline server-certificate revocation for ordinary, unpinned JDK PKIX verification.
 * Install before trust managers, SSL contexts, or clients are initialized.
 * Construction alone does not register the provider or enable path observation.
 * Configuration and diagnostics belong to this instance, not mutable security properties.
 */
public final class UpkiProvider extends Provider {
    private static final long serialVersionUID = 1L;
    public static final String NAME = "UPKI";

    private final ConfiguredChecks checks;
    private final Service[] configuredServices;

    /**
     * Captures security properties once; does not register itself or read cache
     * files.
     */
    public UpkiProvider() {
        this(ProviderConfiguration.load());
    }

    /** Installs first using a fresh security-property snapshot. */
    public static UpkiProvider install() {
        return install(ProviderConfiguration.load());
    }

    /** Creates an unregistered provider without reading cache files. */
    @SuppressWarnings("deprecation")
    public UpkiProvider(UpkiConfiguration configuration) {
        super(NAME, 0.1, "Offline UPKI server-certificate revocation");
        checks = new ConfiguredChecks(Objects.requireNonNull(configuration, "configuration"));
        configuredServices = new Service[] {
            DelegatingService.checkedTrustManagerFactory(this, "PKIX", "PKIX", Collections.emptyList(), checks),
            DelegatingService.checkedTrustManagerFactory(this, "UPKI", "PKIX", Collections.emptyList(), checks),
            new DelegatingService(this, "CertPathValidator", "PKIX", "PKIX", Collections.emptyList()),
            new DelegatingService(this, "CertPathBuilder", "PKIX", "PKIX", Collections.emptyList())
        };
        for (Service service : configuredServices) {
            putService(service);
        }
    }

    /**
     * Installs first, or returns an equivalent intact instance already first.
     * Never replaces or explicitly moves an existing provider, changes the default
     * trust-manager algorithm, resets diagnostics, or retrofits previously
     * initialized verification objects.
     *
     * @throws ProviderException on a name/configuration/priority/service
     *     conflict
     * @throws SecurityException if runtime security policy denies provider
     *     insertion
     */
    public static UpkiProvider install(UpkiConfiguration configuration) {
        Objects.requireNonNull(configuration, "configuration");
        // Public Security insertion/removal methods use this same monitor.
        synchronized (Security.class) {
            Provider[] providers = Security.getProviders();
            Provider existing = Security.getProvider(NAME);
            if (existing != null) {
                if (!(existing instanceof UpkiProvider)) {
                    throw new ProviderException("A different provider already uses " + NAME);
                }
                UpkiProvider provider = (UpkiProvider) existing;
                if (!provider.configuration().equals(configuration)) {
                    throw new ProviderException(NAME + " is already installed with a different configuration");
                }
                if (providers.length == 0 || providers[0] != provider) {
                    throw new ProviderException(NAME + " is installed but is not the first provider");
                }
                provider.requireConfiguredServices();
                return provider;
            }
            UpkiProvider provider = new UpkiProvider(configuration);
            if (Security.insertProviderAt(provider, 1) != 1) {
                throw new ProviderException("Cannot install " + NAME + " as the first provider");
            }
            return provider;
        }
    }

    private void requireConfiguredServices() {
        if (getServices().size() != configuredServices.length) {
            throw new ProviderException(NAME + " services were modified after construction");
        }
        for (Service service : configuredServices) {
            if (getService(service.getType(), service.getAlgorithm()) != service) {
                throw new ProviderException(NAME + " services were modified after construction");
            }
        }
    }

    public UpkiConfiguration configuration() {
        return checks.configuration();
    }

    /**
     * Immutable observation without cache probing; counters cover this provider
     * instance.
     */
    public RevocationDiagnostics diagnostics() {
        return checks.diagnostics();
    }

    /** Service owners and live enforcement state must not be shallow-copied. */
    @Override
    public Object clone() {
        throw new UnsupportedOperationException("Construct a new " + NAME + " provider with explicit configuration");
    }

    private void writeObject(ObjectOutputStream output) throws IOException {
        throw new NotSerializableException(UpkiProvider.class.getName() + " owns live enforcement state");
    }

    private void readObject(ObjectInputStream input) throws IOException {
        throw new InvalidObjectException(UpkiProvider.class.getName() + " requires explicit construction");
    }
}
