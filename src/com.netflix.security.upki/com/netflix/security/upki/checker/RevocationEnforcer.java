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
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import com.netflix.security.upki.checker.AuthenticatedPaths.Path;
import com.netflix.security.upki.checker.CheckDiagnostics.Snapshot;
import com.netflix.security.upki.checker.CheckPolicy.CacheFailure;
import com.netflix.security.upki.checker.CheckPolicy.Handling;

/**
 * Internal acceptance layer, separate from cache lookup and ordinary
 * verification.
 */
public final class RevocationEnforcer implements ServerCertificateCheck {
    private final CacheChecker checker;
    private final CheckPolicy policy;
    private final CheckDiagnostics diagnostics = new CheckDiagnostics();

    public RevocationEnforcer(CacheChecker checker, CheckPolicy policy) {
        this.checker = Objects.requireNonNull(checker, "checker");
        this.policy = Objects.requireNonNull(policy, "policy");
    }

    public Decision assess(RevocationInput input) {
        Objects.requireNonNull(input, "input");
        if (!policy.enabled()) {
            return record(new Decision(Finding.DISABLED, true, Severity.NONE, null));
        }
        CacheChecker.Result result = checker.check(input);
        switch (result.outcome()) {
            case REVOKED:
                return record(new Decision(Finding.REVOKED, false, Severity.ERROR, result));
            case NOT_REVOKED:
                return record(new Decision(Finding.NOT_REVOKED, true, Severity.NONE, result));
            case FAILED:
                return record(new Decision(Finding.FAILED, policy.cacheFailure() == CacheFailure.FAIL_OPEN, Severity.ERROR, result));
            case NO_DATA:
                return record(handling(Finding.NO_DATA, policy.missingIndex(), result));
            case NO_SCTS:
                return record(handling(Finding.NO_SCTS, policy.missingScts(), result));
            case NOT_ENROLLED:
                return record(handling(Finding.NOT_ENROLLED, policy.coverage(), result));
            case NOT_COVERED:
                return record(handling(Finding.NOT_COVERED, policy.coverage(), result));
            default:
                throw new AssertionError(result.outcome());
        }
    }

    public Decision assess(X509Certificate leaf, X509Certificate authenticatedIssuer) throws CertificateException {
        Objects.requireNonNull(leaf, "leaf");
        Objects.requireNonNull(authenticatedIssuer, "authenticatedIssuer");
        if (!policy.enabled()) {
            return record(new Decision(Finding.DISABLED, true, Severity.NONE, null));
        }
        return assess(inputs(leaf, authenticatedIssuer));
    }

    private RevocationInput inputs(X509Certificate leaf, X509Certificate issuer) throws CertificateException {
        try {
            return CertificateInputs.read(leaf, issuer);
        } catch (CertificateException failure) {
            diagnostics.record(new Decision(Finding.INPUT_FAILURE, false, Severity.ERROR, null), failure);
            throw failure;
        }
    }

    @Override
    public void check(X509Certificate leaf, AuthenticatedPaths.Result evidence) throws CertificateException {
        Objects.requireNonNull(leaf, "leaf");
        Objects.requireNonNull(evidence, "evidence");
        if (!policy.enabled()) {
            enforce(record(new Decision(Finding.DISABLED, true, Severity.NONE, null)));
            return;
        }
        if (evidence.truncated()) {
            unsupported(Finding.EVIDENCE_TRUNCATED);
            return;
        }
        if (evidence.paths().isEmpty()) {
            unsupported(Finding.ISSUER_UNAVAILABLE);
            return;
        }
        // Check completeness before decoding or selecting any candidate.
        for (Path path : evidence.paths()) {
            if (path.issuer() == null) {
                unsupported(Finding.ISSUER_UNAVAILABLE);
                return;
            }
        }
        RevocationInput input = null;
        for (Path path : evidence.paths()) {
            RevocationInput candidate = inputs(leaf, path.issuer());
            if (input != null && !Arrays.equals(input.issuerSpkiHash(), candidate.issuerSpkiHash())) {
                // Observed successes need not identify one decisive path in an opaque verifier.
                unsupported(Finding.ISSUER_AMBIGUOUS);
                return;
            }
            input = candidate;
        }
        enforce(assess(input));
    }

    public Snapshot snapshot() {
        return diagnostics.snapshot();
    }

    private void unsupported(Finding finding) throws Rejection {
        enforce(record(handling(finding, policy.unavailableIssuer(), null)));
    }

    private static Decision handling(Finding finding, Handling handling, CacheChecker.Result result) {
        Severity severity = handling == Handling.IGNORE
                ? Severity.NONE
                : handling == Handling.WARN ? Severity.WARNING : Severity.ERROR;
        return new Decision(finding, handling != Handling.FAIL, severity, result);
    }

    private Decision record(Decision decision) {
        diagnostics.record(decision, null);
        return decision;
    }

    private static void enforce(Decision decision) throws Rejection {
        if (!decision.allowed()) {
            throw new Rejection(decision);
        }
    }

    public enum Finding {
        REVOKED,
        NOT_REVOKED,
        NOT_ENROLLED,
        NOT_COVERED,
        NO_SCTS,
        NO_DATA,
        FAILED,
        DISABLED,
        ISSUER_UNAVAILABLE,
        ISSUER_AMBIGUOUS,
        EVIDENCE_TRUNCATED,
        INPUT_FAILURE
    }

    public enum Severity {
        NONE,
        WARNING,
        ERROR
    }

    public static final class Decision {
        private final Finding finding;
        private final boolean allowed;
        private final Severity severity;
        private final CacheChecker.Result cacheResult;

        private Decision(Finding finding, boolean allowed, Severity severity,
                         CacheChecker.Result cacheResult) {
            this.finding = finding;
            this.allowed = allowed;
            this.severity = severity;
            this.cacheResult = cacheResult;
        }

        public Finding finding() {
            return finding;
        }

        public boolean allowed() {
            return allowed;
        }

        public Severity severity() {
            return severity;
        }

        public Optional<CacheChecker.Result> cacheResult() {
            return Optional.ofNullable(cacheResult);
        }
    }

    public static final class Rejection extends CertificateException {
        private static final long serialVersionUID = 1L;
        private final Decision decision;

        private Rejection(Decision decision) {
            super("UPKI revocation policy rejected: " + decision.finding());
            this.decision = decision;
        }

        public Decision decision() {
            return decision;
        }
    }
}
