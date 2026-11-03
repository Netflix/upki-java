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

import java.util.Optional;
import java.util.OptionalLong;

import com.netflix.security.upki.RevocationResult.Finding;
import com.netflix.security.upki.RevocationResult.Operation;

/**
 * Immutable library snapshot with bounded retained state and no I/O on access.
 * Counts are revocation assessments, not TLS handshakes. Policy counters describe
 * configured decisions; a standalone caller may interpret findings differently.
 * No hostname, certificate identifier, or Throwable is retained.
 */
public interface RevocationDiagnostics {
    long assessments();

    long policyAllowed();

    long policyRejected();

    long count(Finding finding);

    long count(Operation operation);

    long cacheFailOpen();

    long cacheFailures();

    long restarts();

    long retryExhaustions();

    CacheState cacheState();

    Severity cacheSeverity();

    /**
     * Describes last-observed cache health only, not complete verification
     * capability.
     */
    boolean degraded();

    long degradationEpisode();

    long cacheVersion();

    Optional<Finding> lastFinding();

    /**
     * Wall-clock milliseconds; first/last failure describe the most recent
     * cache degradation episode.
     */
    OptionalLong firstFailureTime();

    OptionalLong lastFailureTime();

    OptionalLong lastRecoveryTime();

    OptionalLong lastSuccessfulCacheAccess();

    /**
     * Retained after success; may describe a non-cache finding without changing
     * cache health.
     */
    Optional<FailureDetail> lastFailure();

    enum CacheState {
        NOT_CHECKED,
        DISABLED,
        ABSENT,
        USABLE,
        FAILED
    }

    enum Severity {
        NONE,
        WARNING,
        ERROR
    }

    /**
     * Each string is bounded to 256 characters; paths/messages may still be
     * sensitive.
     */
    interface FailureDetail {
        Finding finding();

        Severity severity();

        boolean policyAllowed();

        Optional<Operation> operation();

        Optional<String> path();

        Optional<String> exceptionType();

        String message();
    }
}
