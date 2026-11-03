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

package com.netflix.security.upki;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import com.netflix.security.upki.checker.ConfiguredChecks;

/**
 * Offline revocation lookup, not certificate or hostname verification.
 * Callers must authenticate the leaf and its issuer before supplying them.
 * Instances support concurrent checks and own independent diagnostic lifetimes.
 */
public final class RevocationChecker {
    private final ConfiguredChecks checks;

    /**
     * Captures configuration and discovery candidates, but does not open cache
     * files.
     */
    public RevocationChecker(UpkiConfiguration configuration) {
        checks = new ConfiguredChecks(configuration);
    }

    public UpkiConfiguration configuration() {
        return checks.configuration();
    }

    /**
     * Reports findings and cache failures even when configured policy would
     * reject them. Never establishes certificate trust or throws merely because
     * revocation is confirmed.
     *
     * @throws CertificateException if enabled checking cannot decode
     *     certificate lookup inputs
     * @throws NullPointerException if either certificate is null, including
     *     when disabled
     */
    public RevocationResult check(X509Certificate leaf, X509Certificate authenticatedIssuer) throws CertificateException {
        return checks.assess(leaf, authenticatedIssuer);
    }

    /**
     * Immutable traffic-driven observation; never probes the cache or resets
     * counters.
     */
    public RevocationDiagnostics diagnostics() {
        return checks.diagnostics();
    }
}
