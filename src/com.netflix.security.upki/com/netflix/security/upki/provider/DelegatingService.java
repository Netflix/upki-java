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

package com.netflix.security.upki.provider;

import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.ProviderException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import com.netflix.security.provider.certpath.DelegatingCertPathBuilder;
import com.netflix.security.provider.certpath.DelegatingCertPathValidator;
import com.netflix.security.ssl.DelegatingTrustManagerFactory;
import com.netflix.security.upki.checker.ServerCertificateCheck;

/** Internal service construction, not a registered UPKI provider. */
public final class DelegatingService extends Service {
    private final String delegateAlgorithm;
    private final ServerCertificateCheck serverCheck;

    public DelegatingService(Provider owner, String type, String algorithm,
            String delegateAlgorithm, List<String> aliases) {
        this(owner, type, algorithm, delegateAlgorithm, aliases, null);
    }

    private DelegatingService(Provider owner, String type, String algorithm,
            String delegateAlgorithm, List<String> aliases, ServerCertificateCheck serverCheck) {
        super(owner, type, algorithm, implementation(type), aliases,
                Collections.emptyMap());
        this.delegateAlgorithm = Objects.requireNonNull(delegateAlgorithm, "delegateAlgorithm");
        this.serverCheck = serverCheck;
    }

    public static DelegatingService checkedTrustManagerFactory(Provider owner, String algorithm, String delegateAlgorithm,
            List<String> aliases, ServerCertificateCheck check) {
        return new DelegatingService(owner, "TrustManagerFactory", algorithm, delegateAlgorithm, aliases,
                Objects.requireNonNull(check, "check"));
    }

    @Override
    public Object newInstance(Object parameter) {
        if (parameter != null) {
            throw new InvalidParameterException("This service has no constructor parameter");
        }
        try {
            switch (getType()) {
                case "TrustManagerFactory":
                    return new DelegatingTrustManagerFactory(getProvider(), delegateAlgorithm, serverCheck);
                case "CertPathValidator":
                    return new DelegatingCertPathValidator(getProvider(), delegateAlgorithm);
                case "CertPathBuilder":
                    return new DelegatingCertPathBuilder(getProvider(), delegateAlgorithm);
                default:
                    throw new AssertionError(getType());
            }
        } catch (NoSuchAlgorithmException failure) {
            // JCA would otherwise try a lower-priority provider and lose this wrapper.
            throw new ProviderException("Cannot construct delegate for " + getType() + "." + getAlgorithm(), failure);
        }
    }

    private static String implementation(String type) {
        switch (type) {
            case "TrustManagerFactory":
                return DelegatingTrustManagerFactory.class.getName();
            case "CertPathValidator":
                return DelegatingCertPathValidator.class.getName();
            case "CertPathBuilder":
                return DelegatingCertPathBuilder.class.getName();
            default:
                throw new IllegalArgumentException("Unsupported service type: " + type);
        }
    }
}
