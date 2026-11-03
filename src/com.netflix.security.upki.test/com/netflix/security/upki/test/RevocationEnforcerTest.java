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

package com.netflix.security.upki.test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.netflix.security.upki.checker.AuthenticatedPaths;
import com.netflix.security.upki.checker.CacheChecker;
import com.netflix.security.upki.checker.CacheChecker.Operation;
import com.netflix.security.upki.checker.CacheChecker.Outcome;
import com.netflix.security.upki.checker.CertificateInputs;
import com.netflix.security.upki.checker.CheckDiagnostics.CacheState;
import com.netflix.security.upki.checker.CheckDiagnostics.Snapshot;
import com.netflix.security.upki.checker.CheckPolicy;
import com.netflix.security.upki.checker.CheckPolicy.CacheFailure;
import com.netflix.security.upki.checker.CheckPolicy.Handling;
import com.netflix.security.upki.checker.RevocationEnforcer;
import com.netflix.security.upki.checker.RevocationEnforcer.Decision;
import com.netflix.security.upki.checker.RevocationEnforcer.Finding;
import com.netflix.security.upki.checker.RevocationEnforcer.Rejection;
import com.netflix.security.upki.checker.RevocationEnforcer.Severity;
import com.netflix.security.upki.checker.RevocationInput;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RevocationEnforcerTest {
    @TempDir
    Path directory;

    private static CertificateFixture issuer;
    private static CertificateFixture leaf;

    @BeforeAll
    static void certificates() throws Exception {
        issuer = new CertificateFixture(new byte[] {90}, false, true, null);
        byte[] scts = CertificateFixture.list(CertificateFixture.sct(1, 150, new byte[0], new byte[] {1}));
        leaf = new CertificateFixture(new byte[] {91}, true, true, scts, issuer.keys,
                "CN=localhost");
    }

    @ParameterizedTest
    @EnumSource(Handling.class)
    void missingIndexHasThreeObservableBehaviors(Handling handling) {
        RevocationEnforcer enforcer = enforcer(policy(true, handling, CacheFailure.FAIL_OPEN));
        assertEquals(0, enforcer.snapshot().checks());
        assertEquals(CacheState.NOT_CHECKED, enforcer.snapshot().cacheState());
        assertFalse(enforcer.snapshot()
                            .lastFinding()
                            .isPresent());
        Decision decision = enforcer.assess(input());
        assertEquals(Finding.NO_DATA, decision.finding());
        assertEquals(handling != Handling.FAIL, decision.allowed());
        assertEquals(severity(handling), decision.severity());
        Snapshot snapshot = enforcer.snapshot();
        assertEquals(CacheState.ABSENT, snapshot.cacheState());
        assertEquals(severity(handling), snapshot.cacheSeverity());
        assertEquals(1, snapshot.count(Finding.NO_DATA));
        assertEquals(handling != Handling.IGNORE, snapshot.degraded());
        assertEquals(handling == Handling.IGNORE ? 0 : 1, snapshot.degradationEpisode());
        assertFalse(snapshot.lastSuccessfulCacheAccess().isPresent());
    }

    @ParameterizedTest
    @EnumSource(CacheFailure.class)
    void corruptCachePolicyNeverChangesTheReportedFailure(CacheFailure mode) throws Exception {
        Files.write(directory.resolve("index.bin"), new byte[0]);
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.IGNORE, mode));
        Decision decision = enforcer.assess(input());
        assertEquals(Finding.FAILED, decision.finding());
        assertEquals(mode == CacheFailure.FAIL_OPEN, decision.allowed());
        assertEquals(Outcome.FAILED,
                decision.cacheResult()
                        .get()
                        .outcome());
        assertFalse(decision.cacheResult()
                            .get()
                            .failures()
                            .isEmpty());
        Snapshot snapshot = enforcer.snapshot();
        assertEquals(CacheState.FAILED, snapshot.cacheState());
        assertEquals(Severity.ERROR, snapshot.cacheSeverity());
        assertEquals(mode == CacheFailure.FAIL_OPEN ? 1 : 0, snapshot.cacheFailOpen());
        assertEquals(1, snapshot.count(Operation.INDEX_OPEN));
        assertTrue(snapshot.lastFailure()
                           .get()
                           .path()
                           .get()
                           .endsWith("index.bin"));
        assertEquals(Severity.ERROR,
                snapshot.lastFailure()
                        .get()
                        .severity());
        assertEquals(mode == CacheFailure.FAIL_OPEN,
                snapshot.lastFailure()
                        .get()
                        .allowed());
    }

    @Test
    void confirmedRevocationWinsEvenWhenAnotherFilterFailedAndPolicyIsOpen() throws Exception {
        CacheCheckerTest.publish(directory, new String[] {"broken", "revoked"}, new int[] {0},
                new int[][] {{0, 1}});
        Files.write(directory.resolve("broken"), new byte[0]);
        Files.write(directory.resolve("revoked"), CacheCheckerTest.card(0, 0, true));
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN));
        Decision decision = enforcer.assess(input());
        assertFalse(decision.allowed());
        assertEquals(Finding.REVOKED, decision.finding());
        assertEquals(1,
                decision.cacheResult()
                        .get()
                        .failures()
                        .size());
        assertEquals(CacheState.FAILED, enforcer.snapshot().cacheState());
        assertEquals(1, enforcer.snapshot().cacheFailures());
        assertEquals(0, enforcer.snapshot().cacheFailOpen());
        assertEquals(1, enforcer.snapshot().rejected());
    }

    @Test
    void partialNotRevokedEvidenceRemainsACacheFailure() throws Exception {
        CacheCheckerTest.publish(directory, new String[] {"good", "broken"}, new int[] {0},
                new int[][] {{0, 1}});
        Files.write(directory.resolve("good"), CacheCheckerTest.card(0, 0, false));
        Files.write(directory.resolve("broken"), new byte[0]);
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN));
        Decision decision = enforcer.assess(input());
        assertTrue(decision.allowed());
        assertEquals(Finding.FAILED, decision.finding());
        assertTrue(decision.cacheResult()
                           .get()
                           .observedNotRevoked());
        assertEquals(0, enforcer.snapshot().count(Finding.NOT_REVOKED));
        assertEquals(1, enforcer.snapshot().cacheFailOpen());
    }

    @Test
    void disabledCheckingSkipsCacheAndIssuerAcquisition() throws Exception {
        Files.write(directory.resolve("index.bin"), new byte[0]);
        RevocationEnforcer enforcer = enforcer(policy(false, Handling.FAIL, CacheFailure.FAIL_CLOSED));
        assertEquals(Finding.DISABLED, enforcer.assess(input()).finding());
        AuthenticatedPaths.verify(new X509Certificate[] {leaf.certificate}, enforcer, () -> {});
        assertEquals(2, enforcer.snapshot().count(Finding.DISABLED));
        assertEquals(CacheState.DISABLED, enforcer.snapshot().cacheState());
        assertEquals(0, enforcer.snapshot().cacheFailures());
        assertEquals(0, enforcer.snapshot().rejected());
    }

    @ParameterizedTest
    @EnumSource(Handling.class)
    void missingSctsDoNotRequireAnIndexOrClaimCacheRecovery(Handling handling) throws Exception {
        Files.write(directory.resolve("index.bin"), new byte[0]);
        CheckPolicy policy = new CheckPolicy(true, Handling.FAIL, CacheFailure.FAIL_CLOSED, handling, Handling.IGNORE, Handling.FAIL);
        RevocationEnforcer enforcer = enforcer(policy);
        Decision decision = enforcer.assess(CacheCheckerTest.input());
        assertEquals(Finding.NO_SCTS, decision.finding());
        assertEquals(handling != Handling.FAIL, decision.allowed());
        assertEquals(CacheState.NOT_CHECKED, enforcer.snapshot().cacheState());
        assertEquals(0, enforcer.snapshot().count(Finding.NO_DATA));
        enforcer.assess(input());
        Snapshot failed = enforcer.snapshot();
        enforcer.assess(CacheCheckerTest.input());
        assertEquals(CacheState.FAILED, enforcer.snapshot().cacheState());
        assertEquals(failed.cacheVersion(),
                enforcer.snapshot().cacheVersion());
    }

    @ParameterizedTest
    @EnumSource(Handling.class)
    void uncoveredCertificatesAreNotCacheInfrastructureFailures(Handling handling) throws Exception {
        CacheCheckerTest.publish(directory, new String[0], new int[0],
                new int[0][]);
        RevocationEnforcer enforcer = enforcer(new CheckPolicy(true, Handling.FAIL, CacheFailure.FAIL_CLOSED, Handling.FAIL, handling, Handling.FAIL));
        Decision decision = enforcer.assess(input());
        assertEquals(Finding.NOT_COVERED, decision.finding());
        assertEquals(handling != Handling.FAIL, decision.allowed());
        assertEquals(CacheState.USABLE, enforcer.snapshot().cacheState());
        assertFalse(enforcer.snapshot().degraded());
        assertEquals(0, enforcer.snapshot().cacheFailures());
    }

    @Test
    void unenrolledIssuerUsesCoveragePolicy() throws Exception {
        CacheCheckerTest.publish(directory, new String[] {"other-issuer"}, new int[] {0},
                new int[][] {{0}});
        Files.write(directory.resolve("other-issuer"), CacheCheckerTest.card(1, 0, false));
        RevocationEnforcer enforcer = enforcer(new CheckPolicy(true, Handling.FAIL, CacheFailure.FAIL_CLOSED, Handling.FAIL, Handling.FAIL, Handling.FAIL));
        assertEquals(Finding.NOT_ENROLLED, enforcer.assess(input()).finding());
        assertEquals(1, enforcer.snapshot().rejected());
        assertEquals(CacheState.USABLE, enforcer.snapshot().cacheState());
    }

    @Test
    void userAbsenceDoesNotWarnWhenTheSystemCacheWorks() throws Exception {
        good();
        CacheChecker checker = new CacheChecker(Arrays.asList(directory.resolve("absent-user"), directory));
        RevocationEnforcer enforcer = new RevocationEnforcer(checker, policy(true, Handling.WARN, CacheFailure.FAIL_OPEN));
        assertEquals(Finding.NOT_REVOKED, enforcer.assess(input()).finding());
        assertEquals(0, enforcer.snapshot().count(Finding.NO_DATA));
        assertFalse(enforcer.snapshot().degraded());
    }

    @Test
    void corruptSelectedCacheDoesNotFallBackToAWorkingSystemCache() throws Exception {
        Path user = Files.createDirectory(directory.resolve("user"));
        Files.write(user.resolve("index.bin"), new byte[0]);
        good();
        RevocationEnforcer enforcer = new RevocationEnforcer(new CacheChecker(Arrays.asList(user, directory)), policy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN));
        assertEquals(Finding.FAILED, enforcer.assess(input()).finding());
        assertEquals(0, enforcer.snapshot().count(Finding.NOT_REVOKED));
    }

    @Test
    void retriesAndExhaustionRemainObservable() throws Exception {
        CacheCheckerTest.publish(directory, new String[] {"missing"}, new int[] {0},
                new int[][] {{0}});
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN));
        Decision decision = enforcer.assess(input());
        assertEquals(Finding.FAILED, decision.finding());
        assertTrue(decision.cacheResult()
                           .get()
                           .retryExhausted());
        assertEquals(2, enforcer.snapshot().restarts());
        assertEquals(1, enforcer.snapshot().retryExhaustions());
    }

    @Test
    void recoveryAndNewDegradationHaveStableEpisodeMarkers() throws Exception {
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.WARN, CacheFailure.FAIL_OPEN));
        enforcer.assess(input());
        Snapshot absent = enforcer.snapshot();
        assertEquals(1, absent.degradationEpisode());
        assertTrue(absent.firstFailureTime().isPresent());
        assertTrue(absent.lastFailureTime().isPresent());
        good();
        enforcer.assess(input());
        Snapshot recovered = enforcer.snapshot();
        assertFalse(recovered.degraded());
        assertEquals(1, recovered.degradationEpisode());
        assertTrue(recovered.lastRecoveryTime().isPresent());
        assertTrue(recovered.lastSuccessfulCacheAccess().isPresent());
        assertTrue(recovered.cacheVersion() > absent.cacheVersion());
        Files.delete(directory.resolve("index.bin"));
        enforcer.assess(input());
        assertEquals(2, enforcer.snapshot().degradationEpisode());
        assertTrue(enforcer.snapshot().degraded());
        assertEquals(1, absent.checks());
        assertEquals(CacheState.ABSENT, absent.cacheState());
        assertFalse(absent.lastSuccessfulCacheAccess().isPresent());
    }

    @Test
    void snapshotsDoNotProbeTheFilesystem() throws Exception {
        good();
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.FAIL, CacheFailure.FAIL_CLOSED));
        enforcer.assess(input());
        Snapshot before = enforcer.snapshot();
        Files.write(directory.resolve("index.bin"), new byte[0]);
        Snapshot after = enforcer.snapshot();
        assertEquals(CacheState.USABLE, after.cacheState());
        assertEquals(before.checks(), after.checks());
        assertEquals(before.cacheVersion(), after.cacheVersion());
    }

    @Test
    void failureDetailsAreBoundedAndContainNoThrowable() throws Exception {
        CacheCheckerTest.publish(directory, new String[] {"broken"}, new int[] {0},
                new int[][] {{0}});
        char[] message = new char[10000];
        Arrays.fill(message, 'x');
        IOException failure = new IOException(new String(message));
        CacheChecker checker = new CacheChecker(Collections.singletonList(directory), path -> {
            throw failure;
        });
        RevocationEnforcer enforcer = new RevocationEnforcer(checker, policy(true, Handling.WARN, CacheFailure.FAIL_OPEN));
        enforcer.assess(input());
        assertTrue(enforcer.snapshot()
                           .lastFailure()
                           .get()
                           .message()
                           .length()
                <= 256);
        assertEquals(
                IOException.class.getName(),
                enforcer.snapshot()
                        .lastFailure()
                        .get()
                        .exceptionType()
                        .get());
        assertEquals(1, enforcer.snapshot().count(Operation.FILTER_LOAD));
        for (Field field : enforcer.snapshot()
                .lastFailure()
                .get()
                .getClass()
                .getDeclaredFields()) {
            assertFalse(Throwable.class.isAssignableFrom(field.getType()));
            assertFalse(X509Certificate.class.isAssignableFrom(field.getType()));
        }
    }

    @Test
    void concurrentSnapshotsAndCountersAreCoherent() throws Exception {
        good();
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.WARN, CacheFailure.FAIL_OPEN));
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Callable<Void>> tasks = new ArrayList<>();
            for (int i = 0; i < 200; i++) {
                tasks.add(() -> {
                    assertTrue(enforcer.assess(input()).allowed());
                    Snapshot snapshot = enforcer.snapshot();
                    assertEquals(snapshot.checks(), snapshot.allowed() + snapshot.rejected());
                    return null;
                });
            }
            for (Future<Void> result : pool.invokeAll(tasks)) {
                result.get();
            }
        } finally {
            pool.shutdownNow();
        }
        Snapshot snapshot = enforcer.snapshot();
        assertEquals(200, snapshot.checks());
        assertEquals(200, snapshot.allowed());
        assertEquals(200, snapshot.count(Finding.NOT_REVOKED));
        assertEquals(0, snapshot.rejected());
        assertEquals(1, snapshot.cacheVersion());
    }

    @ParameterizedTest
    @EnumSource(Handling.class)
    void unsupportedVerificationHasItsOwnPolicyAndDoesNotAccessCache(Handling handling) throws Exception {
        Files.write(directory.resolve("index.bin"), new byte[0]);
        RevocationEnforcer enforcer = enforcer(new CheckPolicy(true, Handling.FAIL, CacheFailure.FAIL_CLOSED, Handling.FAIL, Handling.FAIL, handling));
        if (handling == Handling.FAIL) {
            Rejection rejection = assertThrows(Rejection.class,
                    () -> AuthenticatedPaths.verify(chain(), enforcer, () -> {}));
            assertEquals(Finding.ISSUER_UNAVAILABLE, rejection.decision().finding());
        } else {
            AuthenticatedPaths.verify(chain(), enforcer, () -> {});
        }
        assertEquals(CacheState.NOT_CHECKED, enforcer.snapshot().cacheState());
        assertEquals(1, enforcer.snapshot().count(Finding.ISSUER_UNAVAILABLE));
    }

    @Test
    void ambiguousIssuerEncodingIsUnsupportedRatherThanAnArbitraryCacheLookup() throws Exception {
        CertificateFixture alternate = new CertificateFixture(
                new byte[] {92},
                false,
                false,
                null,
                issuer.keys,
                issuer.certificate.getSubjectX500Principal().getName(),
                issuer.keys);
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN));
        Rejection rejection = assertThrows(
                Rejection.class,
                () -> AuthenticatedPaths.verify(chain(), enforcer,
                        () -> {
                            validate(leaf, issuer.certificate);
                            validate(leaf, alternate.certificate);
                        }));
        assertEquals(Finding.ISSUER_AMBIGUOUS, rejection.decision().finding());
        assertEquals(CacheState.NOT_CHECKED, enforcer.snapshot().cacheState());
    }

    @Test
    void pathsWithTheSameOriginalSpkiNeedOnlyOneCacheAssessment() throws Exception {
        CertificateFixture alternate = new CertificateFixture(
                new byte[] {93},
                false,
                true,
                null,
                issuer.keys,
                issuer.certificate.getSubjectX500Principal().getName(),
                issuer.keys);
        CacheFixture.write(directory, CertificateInputs.read(leaf.certificate, issuer.certificate).issuerSpkiHash(),
                false);
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.FAIL, CacheFailure.FAIL_CLOSED));
        AuthenticatedPaths.verify(chain(), enforcer,
                () -> {
                    validate(leaf, issuer.certificate);
                    validate(leaf, alternate.certificate);
                });
        assertEquals(1, enforcer.snapshot().checks());
        assertEquals(1, enforcer.snapshot().count(Finding.NOT_REVOKED));
    }

    @Test
    void truncatedAndKeyOnlyEvidenceAreNotPassedToTheCache() throws Exception {
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN));
        Rejection truncated = assertThrows(Rejection.class,
                () -> AuthenticatedPaths.verify(chain(), enforcer, () -> {
                    for (int i = 0; i < 33; i++) {
                        validate(leaf, issuer.certificate);
                    }
                }));
        assertEquals(Finding.EVIDENCE_TRUNCATED, truncated.decision().finding());
        PKIXParameters parameters = new PKIXParameters(Collections.singleton(new TrustAnchor(issuer.certificate.getSubjectX500Principal(), issuer.certificate.getPublicKey(), null)));
        parameters.setRevocationEnabled(false);
        Rejection missing = assertThrows(Rejection.class,
                () -> AuthenticatedPaths.verify(chain(), enforcer, () -> validate(leaf, parameters)));
        assertEquals(Finding.ISSUER_UNAVAILABLE, missing.decision().finding());
        assertEquals(CacheState.NOT_CHECKED, enforcer.snapshot().cacheState());
    }

    @Test
    void malformedCertificateInputIsNotCoveredByCacheFailOpen() throws Exception {
        CertificateFixture malformed = new CertificateFixture(new byte[] {94}, true, true,
                new byte[] {0, 0}, issuer.keys, "CN=localhost");
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN));
        CertificateException failure = assertThrows(CertificateException.class,
                () -> AuthenticatedPaths.verify(new X509Certificate[] {malformed.certificate}, enforcer, () -> validate(malformed, issuer.certificate)));
        assertFalse(failure instanceof Rejection);
        assertEquals(1, enforcer.snapshot().count(Finding.INPUT_FAILURE));
        assertEquals(1, enforcer.snapshot().rejected());
        assertEquals(CacheState.NOT_CHECKED, enforcer.snapshot().cacheState());
    }

    @Test
    void ordinaryValidationFailureDoesNotRunOrGetCountedAsARevocationAssessment() {
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN));
        CertificateException rejection = new CertificateException("normal verification rejected");
        assertSame(rejection,
                assertThrows(CertificateException.class,
                        () -> AuthenticatedPaths.verify(chain(), enforcer, () -> {
                            throw rejection;
                        })));
        assertEquals(0, enforcer.snapshot().checks());
    }

    @Test
    void cacheSeverityChangesStayWithinOneDegradationEpisode() throws Exception {
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.WARN, CacheFailure.FAIL_OPEN));
        enforcer.assess(input());
        Snapshot missing = enforcer.snapshot();
        Files.write(directory.resolve("index.bin"), new byte[0]);
        enforcer.assess(input());
        Snapshot broken = enforcer.snapshot();
        assertEquals(Severity.ERROR, broken.cacheSeverity());
        assertEquals(1, broken.degradationEpisode());
        assertEquals(missing.firstFailureTime(), broken.firstFailureTime());
        assertTrue(broken.cacheVersion() > missing.cacheVersion());
        enforcer.assess(input());
        assertEquals(broken.cacheVersion(),
                enforcer.snapshot().cacheVersion());
        assertEquals(2, enforcer.snapshot().cacheFailures());
        assertEquals(1, broken.count(Operation.INDEX_OPEN));
        assertFalse(broken.lastRecoveryTime().isPresent());
    }

    @Test
    void acceptedAbsenceDoesNotBecomeASuccessfulCacheRead() {
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN));
        enforcer.assess(input());
        Snapshot snapshot = enforcer.snapshot();
        assertEquals(CacheState.ABSENT, snapshot.cacheState());
        assertFalse(snapshot.lastSuccessfulCacheAccess().isPresent());
        assertFalse(snapshot.firstFailureTime().isPresent());
        assertFalse(snapshot.lastFailure().isPresent());
        assertEquals(0, snapshot.cacheFailOpen());
    }

    @Test
    void unsupportedEvidenceCannotClearAnObservedCacheFailure() throws Exception {
        Files.write(directory.resolve("index.bin"), new byte[0]);
        RevocationEnforcer enforcer = enforcer(new CheckPolicy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN, Handling.IGNORE, Handling.IGNORE, Handling.WARN));
        enforcer.assess(input());
        long version = enforcer.snapshot().cacheVersion();
        AuthenticatedPaths.verify(chain(), enforcer, () -> {});
        Snapshot snapshot = enforcer.snapshot();
        assertEquals(CacheState.FAILED, snapshot.cacheState());
        assertEquals(version, snapshot.cacheVersion());
        assertEquals(1, snapshot.count(Finding.ISSUER_UNAVAILABLE));
        assertEquals(Finding.ISSUER_UNAVAILABLE,
                snapshot.lastFailure()
                        .get()
                        .finding());
        assertEquals(Severity.WARNING,
                snapshot.lastFailure()
                        .get()
                        .severity());
        assertTrue(snapshot.lastFailure()
                           .get()
                           .allowed());
        assertFalse(snapshot.lastRecoveryTime().isPresent());
    }

    @Test
    void confirmedRevocationDoesNotImplyBrokenInfrastructure() throws Exception {
        CacheCheckerTest.publish(directory, new String[] {"revoked"}, new int[] {0},
                new int[][] {{0}});
        Files.write(directory.resolve("revoked"), CacheCheckerTest.card(0, 0, true));
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN));
        Decision decision = enforcer.assess(input());
        assertEquals(Severity.ERROR, decision.severity());
        assertFalse(decision.allowed());
        assertEquals(CacheState.USABLE, enforcer.snapshot().cacheState());
        assertEquals(Severity.NONE, enforcer.snapshot().cacheSeverity());
        assertEquals(Finding.REVOKED,
                enforcer.snapshot()
                        .lastFailure()
                        .get()
                        .finding());
        assertEquals(0, enforcer.snapshot().cacheFailures());
    }

    @Test
    void unexpectedCheckerFailureIsNotAnAllowedCacheFailure() throws Exception {
        CacheCheckerTest.publish(directory, new String[] {"bug"}, new int[] {0},
                new int[][] {{0}});
        IllegalStateException bug = new IllegalStateException("unexpected checker failure");
        CacheChecker checker = new CacheChecker(Collections.singletonList(directory), path -> {
            throw bug;
        });
        RevocationEnforcer enforcer = new RevocationEnforcer(checker, policy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN));
        assertSame(bug, assertThrows(IllegalStateException.class, () -> enforcer.assess(input())));
        assertEquals(0, enforcer.snapshot().cacheFailOpen());
        assertEquals(0, enforcer.snapshot().checks());
    }

    @Test
    void nullInputIsAProgrammingErrorNotFailOpen() {
        RevocationEnforcer enforcer = enforcer(policy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN));
        assertThrows(NullPointerException.class, () -> enforcer.assess(null));
        assertThrows(NullPointerException.class, () -> enforcer.check(leaf.certificate, null));
        assertThrows(NullPointerException.class, () -> new RevocationEnforcer(null, policy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN)));
        assertThrows(NullPointerException.class, () -> new RevocationEnforcer(new CacheChecker(Collections.singletonList(directory)), null));
        assertEquals(0, enforcer.snapshot().checks());
    }

    @Test
    void invalidConfigurationIsRejectedWithoutDefaults() {
        assertThrows(NullPointerException.class, () -> new CheckPolicy(true, null, CacheFailure.FAIL_OPEN, Handling.IGNORE, Handling.IGNORE, Handling.FAIL));
        assertThrows(NullPointerException.class, () -> new CheckPolicy(true, Handling.IGNORE, null, Handling.IGNORE, Handling.IGNORE, Handling.FAIL));
        assertThrows(NullPointerException.class, () -> new CheckPolicy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN, null, Handling.IGNORE, Handling.FAIL));
        assertThrows(NullPointerException.class, () -> new CheckPolicy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN, Handling.IGNORE, null, Handling.FAIL));
        assertThrows(NullPointerException.class, () -> new CheckPolicy(true, Handling.IGNORE, CacheFailure.FAIL_OPEN, Handling.IGNORE, Handling.IGNORE, null));
    }

    private static CheckPolicy policy(boolean enabled, Handling missing, CacheFailure failures) {
        return new CheckPolicy(enabled, missing, failures, Handling.IGNORE, Handling.IGNORE, Handling.FAIL);
    }

    private RevocationEnforcer enforcer(CheckPolicy policy) {
        return new RevocationEnforcer(new CacheChecker(Collections.singletonList(directory)), policy);
    }

    private static RevocationInput input() {
        return CacheCheckerTest.input(CacheCheckerTest.timestamp(0));
    }

    private static X509Certificate[] chain() {
        return new X509Certificate[] {leaf.certificate};
    }

    private void good() throws IOException {
        CacheCheckerTest.publish(directory, new String[] {"good"}, new int[] {0},
                new int[][] {{0}});
        Files.write(directory.resolve("good"), CacheCheckerTest.card(0, 0, false));
    }

    private static Severity severity(Handling handling) {
        return handling == Handling.IGNORE
                ? Severity.NONE
                : handling == Handling.WARN ? Severity.WARNING : Severity.ERROR;
    }

    private static void validate(CertificateFixture target, X509Certificate anchor) throws CertificateException {
        try {
            PKIXParameters parameters = new PKIXParameters(Collections.singleton(new TrustAnchor(anchor, null)));
            parameters.setRevocationEnabled(false);
            validate(target, parameters);
        } catch (InvalidAlgorithmParameterException failure) {
            throw new CertificateException(failure);
        }
    }

    private static void validate(CertificateFixture target, PKIXParameters parameters) throws CertificateException {
        CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(Collections.singletonList(target.certificate));
        AuthenticatedPaths.Operation operation = AuthenticatedPaths.begin();
        try {
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) CertPathValidator.getInstance("PKIX").validate(path, parameters);
            operation.validated(path, result);
        } catch (NoSuchAlgorithmException | CertPathValidatorException | InvalidAlgorithmParameterException failure) {
            throw new CertificateException(failure);
        } finally {
            operation.close();
        }
    }
}
