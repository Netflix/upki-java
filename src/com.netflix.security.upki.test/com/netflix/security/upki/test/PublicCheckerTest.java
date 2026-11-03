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

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.netflix.security.provider.UpkiProvider;
import com.netflix.security.upki.RevocationChecker;
import com.netflix.security.upki.RevocationDiagnostics;
import com.netflix.security.upki.RevocationDiagnostics.CacheState;
import com.netflix.security.upki.RevocationDiagnostics.FailureDetail;
import com.netflix.security.upki.RevocationDiagnostics.Severity;
import com.netflix.security.upki.RevocationResult;
import com.netflix.security.upki.RevocationResult.Failure;
import com.netflix.security.upki.RevocationResult.Finding;
import com.netflix.security.upki.RevocationResult.Operation;
import com.netflix.security.upki.UpkiConfiguration;
import com.netflix.security.upki.UpkiConfiguration.Builder;
import com.netflix.security.upki.UpkiConfiguration.CacheFailure;
import com.netflix.security.upki.UpkiConfiguration.Handling;
import com.netflix.security.upki.checker.AuthenticatedPaths;
import com.netflix.security.upki.checker.AuthenticatedPaths.Verification;
import com.netflix.security.upki.checker.CertificateInputs;
import com.netflix.security.upki.checker.ConfiguredChecks;
import com.netflix.security.upki.checker.RevocationEnforcer.Rejection;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class PublicCheckerTest {
    @TempDir
    Path directory;

    private static CertificateFixture issuer;
    private static CertificateFixture leaf;
    private static CertificateFixture noScts;
    private static CertificateFixture malformed;
    private static byte[] issuerHash;

    @BeforeAll
    static void certificates() throws Exception {
        issuer = new CertificateFixture(new byte[] {100}, false, true, null);
        byte[] scts = CertificateFixture.list(CertificateFixture.sct(1, 150, new byte[0], new byte[] {1}));
        leaf = new CertificateFixture(new byte[] {101}, true, true, scts, issuer.keys,
                "CN=localhost");
        noScts = new CertificateFixture(new byte[] {102}, true, true, null, issuer.keys,
                "CN=localhost");
        malformed = new CertificateFixture(new byte[] {103}, true, true,
                new byte[] {0, 0}, issuer.keys, "CN=localhost");
        issuerHash = CertificateInputs.read(leaf.certificate, issuer.certificate).issuerSpkiHash();
    }

    @Test
    void configurationRequiresExplicitChoicesRatherThanInventingDefaults() {
        assertThrows(IllegalStateException.class,
                () -> UpkiConfiguration.builder().build());
        assertThrows(
                IllegalStateException.class,
                () -> UpkiConfiguration.builder()
                        .enabled(true)
                        .missingIndex(Handling.IGNORE)
                        .cacheFailure(CacheFailure.FAIL_OPEN)
                        .missingScts(Handling.IGNORE)
                        .coverage(Handling.IGNORE)
                        .unsupportedVerification(Handling.WARN)
                        .build());
        assertThrows(
                IllegalStateException.class,
                () -> UpkiConfiguration.builder()
                        .automaticDiscovery()
                        .missingIndex(Handling.IGNORE)
                        .cacheFailure(CacheFailure.FAIL_OPEN)
                        .missingScts(Handling.IGNORE)
                        .coverage(Handling.IGNORE)
                        .unsupportedVerification(Handling.WARN)
                        .build());
        assertThrows(IllegalStateException.class,
                () -> UpkiConfiguration.builder()
                        .automaticDiscovery()
                        .enabled(false)
                        .build());
        UpkiConfiguration automatic = configured(Handling.WARN, CacheFailure.FAIL_OPEN)
                .automaticDiscovery()
                .build();
        assertFalse(automatic.cacheDirectory().isPresent());
        assertTrue(automatic.enabled());
        assertEquals(Handling.WARN, automatic.missingIndex());
        assertEquals(CacheFailure.FAIL_OPEN, automatic.cacheFailure());
        assertEquals(Handling.IGNORE, automatic.missingScts());
        assertEquals(Handling.IGNORE, automatic.coverage());
        assertEquals(Handling.WARN, automatic.unsupportedVerification());
    }

    @Test
    void configurationOwnsItsValuesAndBuilderReuseDoesNotChangeExistingCheckers() throws Exception {
        Builder builder = configured(Handling.IGNORE, CacheFailure.FAIL_OPEN).cacheDirectory(directory);
        UpkiConfiguration first = builder.build();
        RevocationChecker checker = new RevocationChecker(first);
        builder.cacheDirectory(directory.resolve("other"))
               .missingIndex(Handling.FAIL)
               .enabled(false);
        assertSame(first, checker.configuration());
        assertEquals(directory.toAbsolutePath(),
                first.cacheDirectory().get());
        assertEquals(Handling.IGNORE, first.missingIndex());
        assertTrue(first.enabled());
        assertFalse(builder.build().enabled());
        UpkiConfiguration relative = configured(Handling.WARN, CacheFailure.FAIL_OPEN)
                .cacheDirectory(Paths.get("relative", "..", "cache"))
                .build();
        assertEquals(Paths.get("relative", "..", "cache").toAbsolutePath(),
                relative.cacheDirectory().get());
    }

    @Test
    void explicitDirectoryPreservesParentTraversalThroughSymbolicLinks() throws Exception {
        Assumptions.assumeTrue(!System.getProperty("os.name").startsWith("Windows"), "This fixture needs unprivileged symbolic-link creation");
        Path nested = Files.createDirectories(directory.resolve("real/nested"));
        Path intended = Files.createDirectory(directory.resolve("real/cache"));
        Path decoy = Files.createDirectory(directory.resolve("cache"));
        Files.createSymbolicLink(directory.resolve("alias"), nested);
        CacheFixture.write(intended, issuerHash, false);
        CacheFixture.write(decoy, issuerHash, true);
        Path selected = directory.resolve("alias/../cache");
        RevocationChecker checker = new RevocationChecker(configured(Handling.FAIL, CacheFailure.FAIL_CLOSED)
                .cacheDirectory(selected)
                .build());
        assertEquals(Finding.NOT_REVOKED, checker.check(leaf.certificate, issuer.certificate)
                .finding());
        assertEquals(selected.toAbsolutePath(),
                checker.configuration()
                       .cacheDirectory()
                       .get());
    }

    @Test
    void nullConfigurationInputsAreProgrammingErrors() {
        Builder builder = configured(Handling.IGNORE, CacheFailure.FAIL_OPEN);
        assertThrows(NullPointerException.class, () -> builder.cacheDirectory(null));
        assertThrows(NullPointerException.class, () -> builder.missingIndex(null));
        assertThrows(NullPointerException.class, () -> builder.cacheFailure(null));
        assertThrows(NullPointerException.class, () -> builder.missingScts(null));
        assertThrows(NullPointerException.class, () -> builder.coverage(null));
        assertThrows(NullPointerException.class, () -> builder.unsupportedVerification(null));
        assertThrows(NullPointerException.class, () -> new RevocationChecker(null));
    }

    @Test
    void constructionDoesNotProbeCacheOrInstallProviders() throws Exception {
        Files.write(directory.resolve("index.bin"), new byte[0]);
        List<Provider> before = Arrays.asList(Security.getProviders());
        RevocationChecker checker = checker(Handling.FAIL, CacheFailure.FAIL_CLOSED);
        assertEquals(before, Arrays.asList(Security.getProviders()));
        assertEquals(0, checker.diagnostics().assessments());
        assertEquals(CacheState.NOT_CHECKED, checker.diagnostics().cacheState());
        assertFalse(checker.diagnostics()
                           .lastFinding()
                           .isPresent());
    }

    @Test
    void standaloneReportsRevocationWithoutMakingOrThrowingAnAcceptanceDecision() throws Exception {
        CacheFixture.write(directory, issuerHash, false);
        RevocationChecker checker = checker(Handling.FAIL, CacheFailure.FAIL_CLOSED);
        RevocationResult good = checker.check(leaf.certificate, issuer.certificate);
        assertEquals(Finding.NOT_REVOKED, good.finding());
        assertEquals(directory, good.directory().get());
        assertTrue(good.observedNotRevoked());
        assertTrue(good.failures().isEmpty());
        CacheFixture.write(directory, issuerHash, true);
        RevocationResult revoked = checker.check(leaf.certificate, issuer.certificate);
        assertEquals(Finding.REVOKED, revoked.finding());
        assertFalse(revoked.observedNotRevoked());
        assertEquals(Finding.NOT_REVOKED, good.finding());
        assertEquals(2, checker.diagnostics().assessments());
        assertEquals(1, checker.diagnostics().policyAllowed());
        assertEquals(1, checker.diagnostics().policyRejected());
        assertEquals(CacheState.USABLE, checker.diagnostics().cacheState());
    }

    @ParameterizedTest
    @EnumSource(Handling.class)
    void missingIndexReturnsEvidenceEvenUnderRejectingPolicy(Handling handling) throws Exception {
        RevocationChecker checker = checker(handling, CacheFailure.FAIL_CLOSED);
        assertEquals(Finding.NO_DATA, checker.check(leaf.certificate, issuer.certificate)
                .finding());
        RevocationDiagnostics snapshot = checker.diagnostics();
        assertEquals(CacheState.ABSENT, snapshot.cacheState());
        assertEquals(handling == Handling.FAIL ? 1 : 0, snapshot.policyRejected());
        assertEquals(handling == Handling.IGNORE
                ? Severity.NONE
                : handling == Handling.WARN ? Severity.WARNING : Severity.ERROR,
                snapshot.cacheSeverity());
        assertEquals(1, snapshot.count(Finding.NO_DATA));
        assertFalse(snapshot.lastSuccessfulCacheAccess().isPresent());
    }

    @ParameterizedTest
    @EnumSource(CacheFailure.class)
    void corruptCacheReturnsStructuredFailureInBothPolicyModes(CacheFailure mode) throws Exception {
        Files.write(directory.resolve("index.bin"), new byte[0]);
        RevocationChecker checker = checker(Handling.IGNORE, mode);
        RevocationResult failed = checker.check(leaf.certificate, issuer.certificate);
        assertEquals(Finding.FAILED, failed.finding());
        assertEquals(1, failed.failures().size());
        assertEquals(Operation.INDEX_OPEN,
                failed.failures()
                      .get(0)
                      .operation());
        assertEquals(directory.resolve("index.bin"),
                failed.failures()
                      .get(0)
                      .path());
        assertNotNull(failed.failures()
                            .get(0)
                            .cause());
        assertThrows(UnsupportedOperationException.class,
                () -> failed.failures().clear());
        assertEquals(Severity.ERROR, checker.diagnostics().cacheSeverity());
        assertEquals(1, checker.diagnostics().count(Operation.INDEX_OPEN));
        assertEquals(mode == CacheFailure.FAIL_OPEN ? 1 : 0,
                checker.diagnostics().cacheFailOpen());
        FailureDetail detail = checker.diagnostics()
                .lastFailure()
                .get();
        assertEquals(Finding.FAILED, detail.finding());
        assertEquals(Severity.ERROR, detail.severity());
        assertEquals(mode == CacheFailure.FAIL_OPEN, detail.policyAllowed());
        assertEquals(Operation.INDEX_OPEN, detail.operation().get());
        assertTrue(detail.path()
                         .get()
                         .endsWith("index.bin"));
        assertTrue(detail.exceptionType().isPresent());
        assertTrue(detail.message().length() <= 256);
    }

    @Test
    void partialEvidenceAndConfirmedRevocationKeepTheirErrors() throws Exception {
        CacheFixture.write(directory, issuerHash, false);
        Files.write(directory.resolve("broken"), new byte[0]);
        CacheCheckerTest.publish(directory, new String[] {"broken", "test.filter"}, new int[] {1},
                new int[][] {{0, 1}});
        RevocationChecker checker = checker(Handling.IGNORE, CacheFailure.FAIL_OPEN);
        RevocationResult partial = checker.check(leaf.certificate, issuer.certificate);
        assertEquals(Finding.FAILED, partial.finding());
        assertTrue(partial.observedNotRevoked());
        assertEquals(1, partial.failures().size());
        CacheFixture.write(directory, issuerHash, true);
        CacheCheckerTest.publish(directory, new String[] {"broken", "test.filter"}, new int[] {1},
                new int[][] {{0, 1}});
        RevocationResult revoked = checker.check(leaf.certificate, issuer.certificate);
        assertEquals(Finding.REVOKED, revoked.finding());
        assertEquals(1, revoked.failures().size());
        assertEquals(2, checker.diagnostics().cacheFailures());
        assertEquals(1, checker.diagnostics().cacheFailOpen());
        assertEquals(1, checker.diagnostics().policyRejected());
        assertTrue(partial.observedNotRevoked());
    }

    @Test
    void disabledCheckingDoesNotDecodeCertificateInputs() throws Exception {
        Files.write(directory.resolve("index.bin"), new byte[0]);
        UpkiConfiguration configuration = configured(Handling.FAIL, CacheFailure.FAIL_CLOSED)
                .cacheDirectory(directory)
                .enabled(false)
                .build();
        RevocationChecker checker = new RevocationChecker(configuration);
        RevocationResult result = checker.check(malformed.certificate, issuer.certificate);
        assertEquals(Finding.DISABLED, result.finding());
        assertFalse(result.directory().isPresent());
        assertTrue(result.failures().isEmpty());
        assertFalse(result.observedNotRevoked());
        assertEquals(0, result.restarts());
        assertFalse(result.retryExhausted());
        assertEquals(CacheState.DISABLED, checker.diagnostics().cacheState());
        assertEquals(0, checker.diagnostics().cacheFailures());
    }

    @ParameterizedTest
    @EnumSource(Handling.class)
    void noSctsDoesNotRequireAnIndex(Handling handling) throws Exception {
        RevocationChecker checker = new RevocationChecker(configured(Handling.FAIL, CacheFailure.FAIL_CLOSED)
                .cacheDirectory(directory)
                .missingScts(handling)
                .build());
        assertEquals(Finding.NO_SCTS, checker.check(noScts.certificate, issuer.certificate)
                .finding());
        assertEquals(CacheState.NOT_CHECKED, checker.diagnostics().cacheState());
        assertEquals(0, checker.diagnostics().count(Finding.NO_DATA));
        assertEquals(handling == Handling.FAIL ? 1 : 0,
                checker.diagnostics().policyRejected());
        assertFalse(checker.diagnostics().degraded());
    }

    @Test
    void malformedInputsPropagateAndAreDiagnosedWithoutCacheFailOpen() {
        RevocationChecker checker = checker(Handling.IGNORE, CacheFailure.FAIL_OPEN);
        assertThrows(CertificateException.class, () -> checker.check(malformed.certificate, issuer.certificate));
        assertEquals(1, checker.diagnostics().count(Finding.INPUT_FAILURE));
        assertEquals(1, checker.diagnostics().policyRejected());
        assertEquals(0, checker.diagnostics().cacheFailOpen());
        assertEquals(CacheState.NOT_CHECKED, checker.diagnostics().cacheState());
        assertFalse(checker.diagnostics()
                           .lastFailure()
                           .get()
                           .operation()
                           .isPresent());
    }

    @Test
    void missingReferencedFiltersExposeRetryExhaustion() throws Exception {
        CacheCheckerTest.publish(directory, new String[] {"missing"}, new int[] {1},
                new int[][] {{0}});
        RevocationChecker checker = checker(Handling.WARN, CacheFailure.FAIL_OPEN);
        RevocationResult result = checker.check(leaf.certificate, issuer.certificate);
        assertEquals(Finding.FAILED, result.finding());
        assertEquals(2, result.restarts());
        assertTrue(result.retryExhausted());
        assertEquals(2, checker.diagnostics().restarts());
        assertEquals(1, checker.diagnostics().retryExhaustions());
    }

    @Test
    void coverageHasPolicyButIsNotACacheFailure() throws Exception {
        UpkiConfiguration configuration = configured(Handling.FAIL, CacheFailure.FAIL_CLOSED)
                .cacheDirectory(directory)
                .coverage(Handling.FAIL)
                .build();
        RevocationChecker checker = new RevocationChecker(configuration);
        CacheFixture.write(directory, new byte[32], false);
        assertEquals(Finding.NOT_ENROLLED, checker.check(leaf.certificate, issuer.certificate)
                .finding());
        CacheCheckerTest.publish(directory, new String[0], new int[0],
                new int[0][]);
        assertEquals(Finding.NOT_COVERED, checker.check(leaf.certificate, issuer.certificate)
                .finding());
        assertEquals(2, checker.diagnostics().policyRejected());
        assertEquals(CacheState.USABLE, checker.diagnostics().cacheState());
        assertEquals(0, checker.diagnostics().cacheFailures());
    }

    @Test
    void diagnosticSnapshotsAreImmutableAndDoNotProbe() throws Exception {
        RevocationChecker checker = checker(Handling.WARN, CacheFailure.FAIL_OPEN);
        checker.check(leaf.certificate, issuer.certificate);
        RevocationDiagnostics absent = checker.diagnostics();
        assertEquals(1, absent.degradationEpisode());
        assertTrue(absent.firstFailureTime().isPresent());
        assertTrue(absent.lastFailureTime().isPresent());
        CacheFixture.write(directory, issuerHash, false);
        assertEquals(CacheState.ABSENT, checker.diagnostics().cacheState());
        checker.check(leaf.certificate, issuer.certificate);
        RevocationDiagnostics recovered = checker.diagnostics();
        assertFalse(recovered.degraded());
        assertTrue(recovered.lastSuccessfulCacheAccess().isPresent());
        assertTrue(recovered.lastRecoveryTime().isPresent());
        assertTrue(recovered.cacheVersion() > absent.cacheVersion());
        assertEquals(1, absent.assessments());
        assertEquals(CacheState.ABSENT, absent.cacheState());
        assertFalse(absent.lastSuccessfulCacheAccess().isPresent());
        assertEquals(0, recovered.count(Operation.FILTER_LOAD));
        assertThrows(NullPointerException.class, () -> recovered.count((Finding) null));
        assertThrows(NullPointerException.class, () -> recovered.count((Operation) null));
    }

    @Test
    void separateCheckersDoNotShareCountersOrConfiguration() throws Exception {
        CacheFixture.write(directory, issuerHash, true);
        RevocationChecker first = checker(Handling.FAIL, CacheFailure.FAIL_CLOSED);
        RevocationChecker second = new RevocationChecker(configured(Handling.IGNORE, CacheFailure.FAIL_OPEN)
                .cacheDirectory(directory.resolve("other"))
                .build());
        assertEquals(Finding.REVOKED, first.check(leaf.certificate, issuer.certificate)
                .finding());
        assertEquals(0, second.diagnostics().assessments());
        assertEquals(Finding.NO_DATA, second.check(leaf.certificate, issuer.certificate)
                .finding());
        assertEquals(0, first.diagnostics().count(Finding.NO_DATA));
    }

    @Test
    void concurrentPublicChecksAndSnapshotsAreCoherent() throws Exception {
        CacheFixture.write(directory, issuerHash, false);
        RevocationChecker checker = checker(Handling.WARN, CacheFailure.FAIL_OPEN);
        ExecutorService executor = Executors.newFixedThreadPool(4);
        try {
            List<Callable<Void>> tasks = new ArrayList<>();
            for (int i = 0; i < 100; i++) {
                tasks.add(() -> {
                    assertEquals(Finding.NOT_REVOKED, checker.check(leaf.certificate, issuer.certificate)
                            .finding());
                    RevocationDiagnostics snapshot = checker.diagnostics();
                    assertEquals(snapshot.assessments(), snapshot.policyAllowed() + snapshot.policyRejected());
                    return null;
                });
            }
            for (Future<Void> result : executor.invokeAll(tasks)) {
                result.get();
            }
        } finally {
            executor.shutdownNow();
        }
        assertEquals(100, checker.diagnostics().assessments());
        assertEquals(100, checker.diagnostics().count(Finding.NOT_REVOKED));
    }

    @Test
    void nullCertificatesAreNotInconclusiveOrCacheFailOpen() {
        RevocationChecker checker = checker(Handling.IGNORE, CacheFailure.FAIL_OPEN);
        assertThrows(NullPointerException.class, () -> checker.check(null, issuer.certificate));
        assertThrows(NullPointerException.class, () -> checker.check(leaf.certificate, null));
        assertEquals(0, checker.diagnostics().assessments());
    }

    @ParameterizedTest
    @EnumSource(Handling.class)
    void configuredServerBridgeUsesTheSamePolicyAndPublicDiagnostics(Handling handling) throws Exception {
        ConfiguredChecks checks = new ConfiguredChecks(configured(Handling.FAIL, CacheFailure.FAIL_CLOSED)
                .cacheDirectory(directory)
                .unsupportedVerification(handling)
                .build());
        Verification verification = () -> {};
        if (handling == Handling.FAIL) {
            assertThrows(Rejection.class, () -> AuthenticatedPaths.verify(new X509Certificate[] {leaf.certificate}, checks, verification));
        } else {
            AuthenticatedPaths.verify(new X509Certificate[] {leaf.certificate}, checks, verification);
        }
        RevocationDiagnostics snapshot = checks.diagnostics();
        assertEquals(1, snapshot.count(Finding.ISSUER_UNAVAILABLE));
        assertEquals(CacheState.NOT_CHECKED, snapshot.cacheState());
        assertEquals(handling == Handling.FAIL ? 1 : 0, snapshot.policyRejected());
        assertEquals(handling != Handling.IGNORE,
                snapshot.lastFailure().isPresent());
    }

    @Test
    void publicVocabularyCoversAllInternalCategories() throws Exception {
        String[][] mappings = {
            {Finding.class.getName(), "com.netflix.security.upki.checker.RevocationEnforcer$Finding"},
            {Operation.class.getName(), "com.netflix.security.upki.checker.CacheChecker$Operation"},
            {CacheState.class.getName(), "com.netflix.security.upki.checker.CheckDiagnostics$CacheState"},
            {Severity.class.getName(), "com.netflix.security.upki.checker.RevocationEnforcer$Severity"},
            {Handling.class.getName(), "com.netflix.security.upki.checker.CheckPolicy$Handling"},
            {CacheFailure.class.getName(), "com.netflix.security.upki.checker.CheckPolicy$CacheFailure"}
        };
        for (String[] pair : mappings) {
            assertArrayEquals(enumNames(Class.forName(pair[0])), enumNames(Class.forName(pair[1])));
        }
        RevocationDiagnostics snapshot = checker(Handling.IGNORE, CacheFailure.FAIL_OPEN).diagnostics();
        for (Finding finding : Finding.values()) {
            assertEquals(0, snapshot.count(finding));
        }
        for (Operation operation : Operation.values()) {
            assertEquals(0, snapshot.count(operation));
        }
    }

    @Test
    void publicClientRunsInAnIsolatedJvm() throws Exception {
        String executable = System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java";
        Path java = Paths.get(System.getProperty("java.home"), "bin", executable);
        Set<String> locations = new LinkedHashSet<>();
        for (String name : new String[] {
            PublicApiProbe.class.getName(),
            CertificateFixture.class.getName(),
            CacheFixture.class.getName(),
            RevocationChecker.class.getName(),
            RevocationDiagnostics.class.getName(),
            RevocationResult.class.getName(),
            UpkiConfiguration.class.getName(),
            ConfiguredChecks.class.getName(),
            "com.netflix.security.upki.checker.AuthenticatedPaths",
            "com.netflix.security.upki.checker.ServerCertificateCheck",
            "com.netflix.security.upki.checker.CacheChecker",
            "com.netflix.security.upki.checker.CertificateInputs",
            "com.netflix.security.upki.checker.RevocationInput",
            "com.netflix.security.upki.checker.CheckPolicy",
            "com.netflix.security.upki.checker.CheckDiagnostics",
            "com.netflix.security.upki.checker.RevocationEnforcer",
            "com.netflix.security.upki.cache.CacheDiscovery",
            "com.netflix.security.upki.cache.CachePaths",
            "com.netflix.security.upki.cache.RevocationIndex",
            "com.netflix.security.upki.clubcard.Clubcard",
            "com.netflix.security.upki.clubcard.ClubcardReader"
        }) {
            for (Class<?> type : Class.forName(name).getNestMembers()) {
                locations.add(Paths.get(type.getProtectionDomain()
                                            .getCodeSource()
                                            .getLocation()
                                            .toURI())
                        .toString());
            }
        }
        Path output = directory.resolve("public-api.log");
        Process process = new ProcessBuilder(java.toString(), "-cp", String.join(File.pathSeparator, locations), PublicApiProbe.class.getName())
                .redirectErrorStream(true)
                .redirectOutput(output.toFile())
                .start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly().waitFor();
            fail("Public API probe timed out: " + output);
        }
        String report = new String(Files.readAllBytes(output), StandardCharsets.UTF_8);
        assertEquals(0, process.exitValue(), report);
        assertTrue(report.contains("PASS public API"), report);
    }

    private static String[] enumNames(Class<?> type) {
        return Arrays.stream(type.getEnumConstants())
                .map(value -> ((Enum<?>) value).name())
                .toArray(String[]::new);
    }

    @Test
    void publicModuleSurfaceDoesNotExportParsersOrLeakImplementationTypes() {
        Module module = RevocationChecker.class.getModule();
        assertTrue(module.isNamed());
        assertTrue(module.isExported("com.netflix.security.upki"));
        for (String internal : new String[] {"checker", "cache", "clubcard", "provider"}) {
            assertFalse(module.isExported("com.netflix.security.upki." + internal));
        }
        assertTrue(module.isExported("com.netflix.security.provider"));
        for (Class<?> type : new Class<?>[] {
            UpkiConfiguration.class,
            UpkiProvider.class,
            Builder.class,
            RevocationChecker.class,
            RevocationResult.class,
            Failure.class,
            RevocationDiagnostics.class,
            FailureDetail.class
        }) {
            for (Method method : type.getMethods()) {
                noInternalType(method.getGenericReturnType());
                for (Type parameter : method.getGenericParameterTypes()) {
                    noInternalType(parameter);
                }
                for (Type failure : method.getGenericExceptionTypes()) {
                    noInternalType(failure);
                }
            }
            for (Constructor<?> constructor : type.getConstructors()) {
                for (Type parameter : constructor.getGenericParameterTypes()) {
                    noInternalType(parameter);
                }
            }
        }
    }

    private static void noInternalType(Type type) {
        for (String internal : new String[] {".checker.", ".cache.", ".clubcard.", ".upki.provider.", ".provider.certpath.", ".ssl."}) {
            assertFalse(type.getTypeName().contains(internal),
                    type.getTypeName());
        }
    }

    private RevocationChecker checker(Handling missingIndex, CacheFailure cacheFailure) {
        return new RevocationChecker(configured(missingIndex, cacheFailure)
                .cacheDirectory(directory)
                .build());
    }

    private static Builder configured(Handling missingIndex, CacheFailure cacheFailure) {
        return UpkiConfiguration.builder()
                .enabled(true)
                .missingIndex(missingIndex)
                .cacheFailure(cacheFailure)
                .missingScts(Handling.IGNORE)
                .coverage(Handling.IGNORE)
                .unsupportedVerification(Handling.WARN);
    }
}
