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

import java.security.cert.CertificateException;
import java.util.Optional;
import java.util.OptionalLong;

import com.netflix.security.upki.checker.CacheChecker.Failure;
import com.netflix.security.upki.checker.CacheChecker.Operation;
import com.netflix.security.upki.checker.CacheChecker.Outcome;
import com.netflix.security.upki.checker.CacheChecker.Result;
import com.netflix.security.upki.checker.RevocationEnforcer.Decision;
import com.netflix.security.upki.checker.RevocationEnforcer.Finding;
import com.netflix.security.upki.checker.RevocationEnforcer.Severity;

/** Bounded per-enforcer diagnostics. Snapshots never probe the cache. */
public final class CheckDiagnostics {
    private final long[] findings = new long[Finding.values().length];
    private final long[] operations = new long[Operation.values().length];
    private long checks = 0;
    private long allowed = 0;
    private long rejected = 0;
    private long cacheFailOpen = 0;
    private long cacheFailures = 0;
    private long restarts = 0;
    private long retryExhaustions = 0;
    private long degradationEpisode = 0;
    private long cacheVersion = 0;
    private CacheState cacheState = CacheState.NOT_CHECKED;
    private Severity cacheSeverity = Severity.NONE;
    private Finding lastFinding = null;
    private OptionalLong firstFailureTime = OptionalLong.empty();
    private OptionalLong lastFailureTime = OptionalLong.empty();
    private OptionalLong lastRecoveryTime = OptionalLong.empty();
    private OptionalLong lastSuccessfulCacheAccess = OptionalLong.empty();
    private FailureDetail lastFailure = null;

    void record(Decision decision, CertificateException inputFailure) {
        Result result = decision.cacheResult().orElse(null);
        FailureDetail detail = detail(decision, result, inputFailure);
        long[] failuresByOperation = null;
        if (result != null && !result.failures().isEmpty()) {
            failuresByOperation = new long[operations.length];
            for (Failure failure : result.failures()) {
                failuresByOperation[failure.operation().ordinal()]++;
            }
        }
        CacheState observed = null;
        Severity severity = Severity.NONE;
        if (decision.finding() == Finding.DISABLED) {
            observed = CacheState.DISABLED;
        } else if (result != null && result.outcome() != Outcome.NO_SCTS) {
            if (!result.failures().isEmpty()) {
                observed = CacheState.FAILED;
                severity = Severity.ERROR;
            } else if (result.outcome() == Outcome.NO_DATA) {
                observed = CacheState.ABSENT;
                severity = decision.severity();
            } else {
                observed = CacheState.USABLE;
            }
        }
        commit(decision, result, detail, failuresByOperation, observed, severity);
    }

    private synchronized void commit(Decision decision, Result result, FailureDetail detail,
            long[] failuresByOperation, CacheState observed, Severity severity) {
        long now = System.currentTimeMillis();
        checks++;
        if (decision.allowed()) {
            allowed++;
        } else {
            rejected++;
        }
        findings[decision.finding().ordinal()]++;
        lastFinding = decision.finding();
        if (detail != null) {
            lastFailure = detail;
        }
        if (result != null) {
            restarts += result.restarts();
            if (result.retryExhausted()) {
                retryExhaustions++;
            }
            if (failuresByOperation != null) {
                cacheFailures++;
                for (int i = 0; i < operations.length; i++) {
                    operations[i] += failuresByOperation[i];
                }
            }
            if (decision.finding() == Finding.FAILED && decision.allowed()) {
                cacheFailOpen++;
            }
        }
        if (observed == null) {
            return;
        }
        if (cacheState != observed || cacheSeverity != severity) {
            cacheVersion++;
        }
        if (severity != Severity.NONE) {
            if (cacheSeverity == Severity.NONE) {
                degradationEpisode++;
                firstFailureTime = OptionalLong.of(now);
            }
            lastFailureTime = OptionalLong.of(now);
        } else {
            if (cacheSeverity != Severity.NONE) {
                lastRecoveryTime = OptionalLong.of(now);
            }
            if (observed == CacheState.USABLE) {
                lastSuccessfulCacheAccess = OptionalLong.of(now);
            }
        }
        cacheState = observed;
        cacheSeverity = severity;
    }

    public synchronized Snapshot snapshot() {
        return new Snapshot(this);
    }

    private static FailureDetail detail(Decision decision, Result result, CertificateException inputFailure) {
        if (result != null && !result.failures().isEmpty()) {
            Failure failure = result.failures().get(result.failures().size() - 1);
            return new FailureDetail(
                    decision,
                    failure.operation(),
                    failure.path().toString(),
                    failure.cause()
                           .getClass()
                           .getName(),
                    failure.cause().getMessage());
        }
        if (inputFailure != null) {
            return new FailureDetail(
                    decision,
                    null,
                    null,
                    inputFailure.getClass().getName(),
                    inputFailure.getMessage());
        }
        if (decision.severity() != Severity.NONE) {
            return new FailureDetail(decision, null, null, null,
                    decision.finding().name());
        }
        return null;
    }

    public enum CacheState {
        NOT_CHECKED,
        DISABLED,
        ABSENT,
        USABLE,
        FAILED
    }

    public static final class FailureDetail {
        private final Finding finding;
        private final Severity severity;
        private final boolean allowed;
        private final Operation operation;
        private final String path;
        private final String exceptionType;
        private final String message;

        private FailureDetail(Decision decision, Operation operation, String path,
                              String exceptionType, String message) {
            finding = decision.finding();
            severity = decision.severity();
            allowed = decision.allowed();
            this.operation = operation;
            this.path = bounded(path);
            this.exceptionType = bounded(exceptionType);
            this.message = message == null ? "" : bounded(message);
        }

        private static String bounded(String value) {
            return value == null || value.length() <= 256
                    ? value
                    : value.substring(0, 256);
        }

        public Finding finding() {
            return finding;
        }

        public Severity severity() {
            return severity;
        }

        public boolean allowed() {
            return allowed;
        }

        public Optional<Operation> operation() {
            return Optional.ofNullable(operation);
        }

        public Optional<String> path() {
            return Optional.ofNullable(path);
        }

        public Optional<String> exceptionType() {
            return Optional.ofNullable(exceptionType);
        }

        public String message() {
            return message;
        }
    }

    public static final class Snapshot {
        private final long[] findings;
        private final long[] operations;
        private final long checks;
        private final long allowed;
        private final long rejected;
        private final long cacheFailOpen;
        private final long cacheFailures;
        private final long restarts;
        private final long retryExhaustions;
        private final long degradationEpisode;
        private final long cacheVersion;
        private final CacheState cacheState;
        private final Severity cacheSeverity;
        private final Finding lastFinding;
        private final OptionalLong firstFailureTime;
        private final OptionalLong lastFailureTime;
        private final OptionalLong lastRecoveryTime;
        private final OptionalLong lastSuccessfulCacheAccess;
        private final FailureDetail lastFailure;

        private Snapshot(CheckDiagnostics source) {
            findings = source.findings.clone();
            operations = source.operations.clone();
            checks = source.checks;
            allowed = source.allowed;
            rejected = source.rejected;
            cacheFailOpen = source.cacheFailOpen;
            cacheFailures = source.cacheFailures;
            restarts = source.restarts;
            retryExhaustions = source.retryExhaustions;
            degradationEpisode = source.degradationEpisode;
            cacheVersion = source.cacheVersion;
            cacheState = source.cacheState;
            cacheSeverity = source.cacheSeverity;
            lastFinding = source.lastFinding;
            firstFailureTime = source.firstFailureTime;
            lastFailureTime = source.lastFailureTime;
            lastRecoveryTime = source.lastRecoveryTime;
            lastSuccessfulCacheAccess = source.lastSuccessfulCacheAccess;
            lastFailure = source.lastFailure;
        }

        public long count(Finding finding) {
            return findings[finding.ordinal()];
        }

        public long count(Operation operation) {
            return operations[operation.ordinal()];
        }

        public boolean degraded() {
            return cacheSeverity != Severity.NONE;
        }

        public Optional<Finding> lastFinding() {
            return Optional.ofNullable(lastFinding);
        }

        public Optional<FailureDetail> lastFailure() {
            return Optional.ofNullable(lastFailure);
        }

        public long checks() {
            return checks;
        }

        public long allowed() {
            return allowed;
        }

        public long rejected() {
            return rejected;
        }

        public long cacheFailOpen() {
            return cacheFailOpen;
        }

        public long cacheFailures() {
            return cacheFailures;
        }

        public long restarts() {
            return restarts;
        }

        public long retryExhaustions() {
            return retryExhaustions;
        }

        public long degradationEpisode() {
            return degradationEpisode;
        }

        public long cacheVersion() {
            return cacheVersion;
        }

        public CacheState cacheState() {
            return cacheState;
        }

        public Severity cacheSeverity() {
            return cacheSeverity;
        }

        public OptionalLong firstFailureTime() {
            return firstFailureTime;
        }

        public OptionalLong lastFailureTime() {
            return lastFailureTime;
        }

        public OptionalLong lastRecoveryTime() {
            return lastRecoveryTime;
        }

        public OptionalLong lastSuccessfulCacheAccess() {
            return lastSuccessfulCacheAccess;
        }
    }
}
