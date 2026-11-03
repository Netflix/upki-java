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

package com.netflix.security.upki.checker;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

import com.netflix.security.upki.RevocationDiagnostics;
import com.netflix.security.upki.RevocationDiagnostics.Severity;
import com.netflix.security.upki.RevocationResult;
import com.netflix.security.upki.RevocationResult.Finding;
import com.netflix.security.upki.RevocationResult.Operation;
import com.netflix.security.upki.UpkiConfiguration;
import com.netflix.security.upki.cache.CachePaths;
import com.netflix.security.upki.checker.CheckDiagnostics.Snapshot;
import com.netflix.security.upki.checker.CheckPolicy.CacheFailure;
import com.netflix.security.upki.checker.RevocationEnforcer.Decision;

/** One configuration, enforcement identity, and diagnostic lifetime per owner. */
public final class ConfiguredChecks implements ServerCertificateCheck {
    private final UpkiConfiguration configuration;
    private final RevocationEnforcer enforcer;

    public ConfiguredChecks(UpkiConfiguration configuration) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        List<Path> directories;
        if (!configuration.enabled()) {
            directories = Collections.emptyList();
        } else if (configuration.cacheDirectory().isPresent()) {
            directories = Collections.singletonList(configuration.cacheDirectory()
                    .get());
        } else {
            directories = CachePaths.defaults();
        }
        CheckPolicy policy = new CheckPolicy(
                configuration.enabled(),
                handling(configuration.missingIndex()),
                CacheFailure.valueOf(configuration.cacheFailure().name()),
                handling(configuration.missingScts()),
                handling(configuration.coverage()),
                handling(configuration.unsupportedVerification()));
        enforcer = new RevocationEnforcer(new CacheChecker(directories), policy);
    }

    private static CheckPolicy.Handling handling(UpkiConfiguration.Handling handling) {
        return CheckPolicy.Handling.valueOf(handling.name());
    }

    public UpkiConfiguration configuration() {
        return configuration;
    }

    public RevocationResult assess(X509Certificate leaf, X509Certificate authenticatedIssuer) throws CertificateException {
        return new ResultView(enforcer.assess(leaf, authenticatedIssuer));
    }

    @Override
    public void check(X509Certificate leaf, AuthenticatedPaths.Result evidence) throws CertificateException {
        enforcer.check(leaf, evidence);
    }

    public RevocationDiagnostics diagnostics() {
        return new SnapshotView(enforcer.snapshot());
    }

    private static Finding finding(RevocationEnforcer.Finding finding) {
        return Finding.valueOf(finding.name());
    }

    private static Operation operation(CacheChecker.Operation operation) {
        return Operation.valueOf(operation.name());
    }

    private static final class ResultView implements RevocationResult {
        private final Finding finding;
        private final Path directory;
        private final List<Failure> failures;
        private final boolean observedNotRevoked;
        private final int restarts;
        private final boolean retryExhausted;

        ResultView(Decision decision) {
            finding = ConfiguredChecks.finding(decision.finding());
            CacheChecker.Result result = decision.cacheResult().orElse(null);
            directory = result == null ? null : result.directory().orElse(null);
            List<Failure> retained = new ArrayList<Failure>();
            if (result != null) {
                for (CacheChecker.Failure failure : result.failures()) {
                    retained.add(new FailureView(failure));
                }
            }
            failures = Collections.unmodifiableList(retained);
            observedNotRevoked = result != null && result.observedNotRevoked();
            restarts = result == null ? 0 : result.restarts();
            retryExhausted = result != null && result.retryExhausted();
        }

        public Finding finding() {
            return finding;
        }

        public Optional<Path> directory() {
            return Optional.ofNullable(directory);
        }

        public List<Failure> failures() {
            return failures;
        }

        public boolean observedNotRevoked() {
            return observedNotRevoked;
        }

        public int restarts() {
            return restarts;
        }

        public boolean retryExhausted() {
            return retryExhausted;
        }
    }

    private static final class FailureView implements RevocationResult.Failure {
        private final CacheChecker.Failure source;

        FailureView(CacheChecker.Failure source) {
            this.source = source;
        }

        public Operation operation() {
            return ConfiguredChecks.operation(source.operation());
        }

        public Path path() {
            return source.path();
        }

        public IOException cause() {
            return source.cause();
        }
    }

    private static final class SnapshotView implements RevocationDiagnostics {
        private final Snapshot source;

        SnapshotView(Snapshot source) {
            this.source = source;
        }

        public long count(Finding finding) {
            return source.count(RevocationEnforcer.Finding.valueOf(Objects.requireNonNull(finding, "finding")
                    .name()));
        }

        public long count(Operation operation) {
            return source.count(CacheChecker.Operation.valueOf(Objects.requireNonNull(operation, "operation")
                    .name()));
        }

        public CacheState cacheState() {
            return CacheState.valueOf(source.cacheState().name());
        }

        public Severity cacheSeverity() {
            return Severity.valueOf(source.cacheSeverity().name());
        }

        public Optional<Finding> lastFinding() {
            return source.lastFinding().map(ConfiguredChecks::finding);
        }

        public Optional<FailureDetail> lastFailure() {
            return source.lastFailure().map(DetailView::new);
        }

        public long assessments() {
            return source.checks();
        }

        public long policyAllowed() {
            return source.allowed();
        }

        public long policyRejected() {
            return source.rejected();
        }

        public long cacheFailOpen() {
            return source.cacheFailOpen();
        }

        public long cacheFailures() {
            return source.cacheFailures();
        }

        public long restarts() {
            return source.restarts();
        }

        public long retryExhaustions() {
            return source.retryExhaustions();
        }

        public long degradationEpisode() {
            return source.degradationEpisode();
        }

        public long cacheVersion() {
            return source.cacheVersion();
        }

        public boolean degraded() {
            return source.degraded();
        }

        public OptionalLong firstFailureTime() {
            return source.firstFailureTime();
        }

        public OptionalLong lastFailureTime() {
            return source.lastFailureTime();
        }

        public OptionalLong lastRecoveryTime() {
            return source.lastRecoveryTime();
        }

        public OptionalLong lastSuccessfulCacheAccess() {
            return source.lastSuccessfulCacheAccess();
        }
    }

    private static final class DetailView implements RevocationDiagnostics.FailureDetail {
        private final CheckDiagnostics.FailureDetail source;

        DetailView(CheckDiagnostics.FailureDetail source) {
            this.source = source;
        }

        public Finding finding() {
            return ConfiguredChecks.finding(source.finding());
        }

        public Severity severity() {
            return Severity.valueOf(source.severity().name());
        }

        public boolean policyAllowed() {
            return source.allowed();
        }

        public Optional<Operation> operation() {
            return source.operation().map(ConfiguredChecks::operation);
        }

        public Optional<String> path() {
            return source.path();
        }

        public Optional<String> exceptionType() {
            return source.exceptionType();
        }

        public String message() {
            return source.message();
        }
    }
}
