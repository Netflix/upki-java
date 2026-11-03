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

import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider.Service;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import com.netflix.security.upki.checker.AuthenticatedPaths;
import com.netflix.security.upki.checker.AuthenticatedPaths.Operation;
import com.netflix.security.upki.checker.AuthenticatedPaths.Result;
import com.netflix.security.upki.checker.ServerCertificateCheck;
import com.netflix.security.upki.provider.DelegatingService;
import com.netflix.security.upki.test.DelegateFactoryTest.Providers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class AuthenticatedPathsTest {
    private static CertificateFixture issuer;
    private static CertificateFixture leaf;
    private static CertificateFixture intermediate;
    private static CertificateFixture intermediateLeaf;
    private static CertificateFixture other;

    @BeforeAll
    static void certificates() throws Exception {
        issuer = new CertificateFixture(new byte[] {70}, false, true, null);
        leaf = CertificateFixture.issued(new byte[] {71}, issuer, "CN=localhost");
        intermediate = CertificateFixture.authority(new byte[] {72}, issuer, "CN=intermediate");
        intermediateLeaf = CertificateFixture.issued(new byte[] {73}, intermediate, "CN=localhost");
        other = CertificateFixture.issued(new byte[] {74}, issuer, "CN=other");
    }

    @Test
    void validatorExposesTheActualPathAndAnchorAfterSuccess() throws Exception {
        try (Fixture fixture = new Fixture()) {
            List<Result> results = new ArrayList<>();
            CertPath path = path(leaf.certificate);
            AuthenticatedPaths.verify(
                    chain(leaf),
                    (target, result) -> {
                        assertSame(leaf.certificate, target);
                        results.add(result);
                    },
                    () -> fixture.validate(path, parameters()));
            Result result = results.get(0);
            assertEquals(1, result.paths().size());
            assertFalse(result.truncated());
            assertSame(path,
                    result.paths()
                          .get(0)
                          .certPath());
            assertSame(issuer.certificate,
                    result.paths()
                          .get(0)
                          .trustAnchor()
                          .getTrustedCert());
            assertSame(issuer.certificate,
                    result.paths()
                          .get(0)
                          .issuer());
            assertThrows(UnsupportedOperationException.class,
                    () -> result.paths().clear());
        }
    }

    @Test
    void builderExposesAnIntermediateAbsentFromThePeerInput() throws Exception {
        try (Fixture fixture = new Fixture()) {
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(intermediateLeaf.certificate);
            PKIXBuilderParameters parameters = new PKIXBuilderParameters(parameters().getTrustAnchors(), target);
            parameters.setRevocationEnabled(false);
            parameters.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(Arrays.asList(intermediateLeaf.certificate, intermediate.certificate))));
            AuthenticatedPaths.verify(
                    chain(intermediateLeaf),
                    (checked, result) -> {
                        assertEquals(1, result.paths().size());
                        assertEquals(intermediate.certificate,
                                result.paths()
                                      .get(0)
                                      .issuer());
                        assertEquals(
                                2,
                                result.paths()
                                      .get(0)
                                      .certPath()
                                      .getCertificates()
                                      .size());
                    },
                    () -> {
                        try {
                            CertPathBuilder.getInstance(fixture.providers.algorithm).build(parameters);
                        } catch (NoSuchAlgorithmException | CertPathBuilderException | InvalidAlgorithmParameterException failure) {
                            throw new CertificateException(failure);
                        }
                    });
        }
    }

    @Test
    void noObservationAndKeyOnlyAnchorRemainExplicitlyUnavailable() throws Exception {
        try (Fixture fixture = new Fixture()) {
            AuthenticatedPaths.verify(
                    chain(leaf),
                    (target, result) -> assertTrue(result.paths().isEmpty()),
                    () -> {});
            PKIXParameters parameters = new PKIXParameters(Collections.singleton(new TrustAnchor(issuer.certificate.getSubjectX500Principal(), issuer.certificate.getPublicKey(), null)));
            parameters.setRevocationEnabled(false);
            AuthenticatedPaths.verify(
                    chain(leaf),
                    (target, result) -> {
                        assertEquals(1, result.paths().size());
                        assertNull(result.paths()
                                         .get(0)
                                         .issuer());
                    },
                    () -> fixture.validate(path(leaf.certificate), parameters));
        }
    }

    @Test
    void rejectionAfterPkixSuccessNeverRunsEnforcement() throws Exception {
        try (Fixture fixture = new Fixture()) {
            AtomicInteger checks = new AtomicInteger();
            CertificateException rejection = new CertificateException("outer policy rejected");
            assertSame(rejection,
                    assertThrows(
                            CertificateException.class,
                            () -> AuthenticatedPaths.verify(chain(leaf), (target, result) -> checks.incrementAndGet(),
                                    () -> {
                                        fixture.validate(path(leaf.certificate), parameters());
                                        throw rejection;
                                    })));
            assertEquals(0, checks.get());
            AuthenticatedPaths.verify(
                    chain(leaf),
                    (target, result) -> assertTrue(result.paths().isEmpty()),
                    () -> {});
        }
    }

    @Test
    void enforcementRejectionPropagatesUnchangedAndDoesNotLeakTheScope() throws Exception {
        try (Fixture fixture = new Fixture()) {
            CertificateException revoked = new CertificateException("confirmed revoked");
            assertSame(revoked,
                    assertThrows(
                            CertificateException.class,
                            () -> AuthenticatedPaths.verify(
                                    chain(leaf),
                                    (target, result) -> {
                                        throw revoked;
                                    },
                                    () -> fixture.validate(path(leaf.certificate), parameters()))));
            AuthenticatedPaths.verify(
                    chain(leaf),
                    (target, result) -> assertTrue(result.paths().isEmpty()),
                    () -> {});
        }
    }

    @Test
    void nestedForwardingEnforcesOnceAfterTheOutermostWrapper() throws Exception {
        try (Fixture fixture = new Fixture()) {
            List<String> events = new ArrayList<>();
            ServerCertificateCheck check = (target, result) -> {
                assertEquals(1, result.paths().size());
                events.add("enforce");
            };
            AuthenticatedPaths.verify(chain(leaf), check,
                    () -> {
                        events.add("before");
                        AuthenticatedPaths.verify(chain(leaf), check,
                                () -> fixture.validate(path(leaf.certificate), parameters()));
                        events.add("after");
                    });
            assertEquals(Arrays.asList("before", "after", "enforce"), events);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void caughtInnerTrustManagerFailureRollsBackItsObservedPaths(boolean existingPath) throws Exception {
        try (Fixture fixture = new Fixture()) {
            CertificateException rejection = new CertificateException("inner wrapper rejected after PKIX success");
            ServerCertificateCheck check = (certificate, result) -> {
                assertEquals(existingPath ? 2 : 1,
                        result.paths().size());
                assertFalse(result.truncated());
            };
            AuthenticatedPaths.verify(chain(leaf), check,
                    () -> {
                        if (existingPath) {
                            fixture.validate(path(leaf.certificate), parameters());
                        }
                        assertSame(rejection,
                                assertThrows(CertificateException.class,
                                        () -> AuthenticatedPaths.verify(chain(leaf), check, () -> {
                                            for (int i = 0; i < 33; i++) {
                                                fixture.validate(path(leaf.certificate), parameters());
                                            }
                                            throw rejection;
                                        })));
                        fixture.validate(path(leaf.certificate), parameters());
                    });
        }
    }

    @Test
    void differentLeavesGetIndependentScopesAndOtherLeafOperationsAreIgnored() throws Exception {
        try (Fixture fixture = new Fixture()) {
            List<X509Certificate> checked = new ArrayList<>();
            ServerCertificateCheck check = (target, result) -> {
                assertEquals(1, result.paths().size());
                assertEquals(
                        target,
                        result.paths()
                              .get(0)
                              .certPath()
                              .getCertificates()
                              .get(0));
                checked.add(target);
            };
            AuthenticatedPaths.verify(chain(leaf), check,
                    () -> {
                        fixture.validate(path(other.certificate), parameters());
                        AuthenticatedPaths.verify(chain(other), check,
                                () -> fixture.validate(path(other.certificate), parameters()));
                        fixture.validate(path(leaf.certificate), parameters());
                    });
            assertEquals(Arrays.asList(other.certificate, leaf.certificate), checked);
        }
    }

    @Test
    void failedOuterBuilderCannotPublishAnInnerValidatorSuccess() throws Exception {
        try (Fixture fixture = new Fixture()) {
            String algorithm = fixture.providers.algorithm + "-rejecting";
            CertPathBuilderException rejection = new CertPathBuilderException("outer builder rejected");
            fixture.providers.base.add(
                    new Service(
                            fixture.providers.base,
                            "CertPathBuilder",
                            algorithm,
                            getClass().getName(),
                            null,
                            null) {
                        public Object newInstance(Object unused) {
                            return new CertPathBuilderSpi() {
                                public CertPathBuilderResult engineBuild(CertPathParameters parameters) throws CertPathBuilderException {
                                    try {
                                        fixture.validate(path(other.certificate), parameters());
                                        fixture.validate(path(leaf.certificate), parameters());
                                    } catch (CertificateException failure) {
                                        throw new CertPathBuilderException(failure);
                                    }
                                    throw rejection;
                                }
                            };
                        }
                    });
            String observed = algorithm + "-observed";
            fixture.providers.owner.add(new DelegatingService(fixture.providers.owner, "CertPathBuilder", observed, algorithm, null));
            AuthenticatedPaths.verify(
                    chain(leaf),
                    (target, result) -> assertEquals(1, result.paths().size()),
                    () -> {
                        assertSame(
                                rejection,
                                assertThrows(CertPathBuilderException.class,
                                        () -> CertPathBuilder.getInstance(observed).build(parameters())));
                        fixture.validate(path(leaf.certificate), parameters());
                    });
        }
    }

    @Test
    void boundedEvidenceReportsTruncationInsteadOfSilentlyDroppingCandidates() throws Exception {
        try (Fixture fixture = new Fixture()) {
            AuthenticatedPaths.verify(
                    chain(leaf),
                    (target, result) -> {
                        assertEquals(32, result.paths().size());
                        assertTrue(result.truncated());
                    },
                    () -> {
                        for (int i = 0; i < 33; i++) {
                            fixture.validate(path(leaf.certificate), parameters());
                        }
                    });
            AuthenticatedPaths.verify(
                    chain(leaf),
                    (target, result) -> {
                        assertTrue(result.paths().isEmpty());
                        assertFalse(result.truncated());
                    },
                    () -> {});
        }
    }

    @Test
    void concurrentChecksAreIsolated() throws Exception {
        try (Fixture fixture = new Fixture()) {
            ConcurrentLinkedQueue<X509Certificate> checked = new ConcurrentLinkedQueue<>();
            ExecutorService pool = Executors.newFixedThreadPool(8);
            try {
                List<Callable<Void>> tasks = new ArrayList<>();
                for (int i = 0; i < 80; i++) {
                    CertificateFixture target = i % 2 == 0 ? leaf : other;
                    tasks.add(() -> {
                        AuthenticatedPaths.verify(
                                chain(target),
                                (certificate, result) -> {
                                    assertEquals(1, result.paths().size());
                                    assertEquals(
                                            certificate,
                                            result.paths()
                                                  .get(0)
                                                  .certPath()
                                                  .getCertificates()
                                                  .get(0));
                                    checked.add(certificate);
                                },
                                () -> fixture.validate(path(target.certificate), parameters()));
                        return null;
                    });
                }
                for (Future<Void> task : pool.invokeAll(tasks)) {
                    task.get();
                }
                assertEquals(80, checked.size());
            } finally {
                pool.shutdownNow();
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"basic", "socket", "engine"})
    void extendedTrustManagerForwardsAllOverloadsAndOnlyEnforcesServers(String overload) throws Exception {
        try (Fixture fixture = new Fixture();
             Socket socket = new Socket()) {
            List<String> events = new ArrayList<>();
            Object[] context = new Object[1];
            X509Certificate[] accepted = {issuer.certificate};
            X509Certificate[] input = chain(leaf);
            X509ExtendedTrustManager original = new X509ExtendedTrustManager() {
                private void server(X509Certificate[] chain, String auth, String method,
                                    Object value)
                        throws CertificateException {
                    assertSame(input, chain);
                    assertEquals("auth", auth);
                    context[0] = value;
                    fixture.validate(path(leaf.certificate), parameters());
                    events.add(method);
                }

                public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
                    server(chain, auth, "server.basic", null);
                }

                public void checkServerTrusted(X509Certificate[] chain, String auth, Socket value) throws CertificateException {
                    server(chain, auth, "server.socket", value);
                }

                public void checkServerTrusted(X509Certificate[] chain, String auth, SSLEngine value) throws CertificateException {
                    server(chain, auth, "server.engine", value);
                }

                public void checkClientTrusted(X509Certificate[] chain, String auth) {
                    events.add("client.basic");
                }

                public void checkClientTrusted(X509Certificate[] chain, String auth, Socket value) {
                    context[0] = value;
                    events.add("client.socket");
                }

                public void checkClientTrusted(X509Certificate[] chain, String auth, SSLEngine value) {
                    context[0] = value;
                    events.add("client.engine");
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return accepted;
                }
            };
            X509TrustManager manager = fixture.manager(original,
                    (certificate, result) -> {
                        assertEquals(1, result.paths().size());
                        events.add("enforce");
                    });
            X509ExtendedTrustManager extended = assertInstanceOf(X509ExtendedTrustManager.class, manager);
            SSLEngine engine = SSLContext.getDefault().createSSLEngine();
            switch (overload) {
                case "basic":
                    extended.checkServerTrusted(input, "auth");
                    extended.checkClientTrusted(input, "auth");
                    assertNull(context[0]);
                    break;
                case "socket":
                    extended.checkServerTrusted(input, "auth", socket);
                    assertSame(socket, context[0]);
                    extended.checkClientTrusted(input, "auth", socket);
                    assertSame(socket, context[0]);
                    break;
                case "engine":
                    extended.checkServerTrusted(input, "auth", engine);
                    assertSame(engine, context[0]);
                    extended.checkClientTrusted(input, "auth", engine);
                    assertSame(engine, context[0]);
                    break;
                default:
                    throw new AssertionError(overload);
            }
            assertEquals(Arrays.asList("server." + overload, "enforce", "client." + overload),
                    events);
            assertSame(accepted, manager.getAcceptedIssuers());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"server-basic", "server-socket", "server-engine", "client-basic", "client-socket", "client-engine"})
    void extendedTrustManagerPreservesEachDelegatedRejection(String overload) throws Exception {
        try (Fixture fixture = new Fixture();
             Socket socket = new Socket()) {
            CertificateException rejection = new CertificateException("delegate rejected " + overload);
            AtomicInteger checks = new AtomicInteger();
            X509ExtendedTrustManager original = new X509ExtendedTrustManager() {
                public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
                    throw rejection;
                }

                public void checkServerTrusted(X509Certificate[] chain, String auth, Socket value) throws CertificateException {
                    throw rejection;
                }

                public void checkServerTrusted(X509Certificate[] chain, String auth, SSLEngine value) throws CertificateException {
                    throw rejection;
                }

                public void checkClientTrusted(X509Certificate[] chain, String auth) throws CertificateException {
                    throw rejection;
                }

                public void checkClientTrusted(X509Certificate[] chain, String auth, Socket value) throws CertificateException {
                    throw rejection;
                }

                public void checkClientTrusted(X509Certificate[] chain, String auth, SSLEngine value) throws CertificateException {
                    throw rejection;
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
            X509ExtendedTrustManager manager = (X509ExtendedTrustManager) fixture.manager(original, (certificate, result) -> checks.incrementAndGet());
            SSLEngine engine = SSLContext.getDefault().createSSLEngine();
            CertificateException actual = assertThrows(CertificateException.class, () -> {
                switch (overload) {
                    case "server-basic":
                        manager.checkServerTrusted(chain(leaf), "RSA");
                        break;
                    case "server-socket":
                        manager.checkServerTrusted(chain(leaf), "RSA", socket);
                        break;
                    case "server-engine":
                        manager.checkServerTrusted(chain(leaf), "RSA", engine);
                        break;
                    case "client-basic":
                        manager.checkClientTrusted(chain(leaf), "RSA");
                        break;
                    case "client-socket":
                        manager.checkClientTrusted(chain(leaf), "RSA", socket);
                        break;
                    case "client-engine":
                        manager.checkClientTrusted(chain(leaf), "RSA", engine);
                        break;
                    default:
                        throw new AssertionError(overload);
                }
            });
            assertSame(rejection, actual);
            assertEquals(0, checks.get());
        }
    }

    @Test
    void basicTrustManagersAreNotPromotedAndClientRejectionIsPreserved() throws Exception {
        try (Fixture fixture = new Fixture()) {
            CertificateException clientRejection = new CertificateException("client rejected");
            AtomicInteger checks = new AtomicInteger();
            X509TrustManager original = new X509TrustManager() {
                public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
                    fixture.validate(path(leaf.certificate), parameters());
                }

                public void checkClientTrusted(X509Certificate[] chain, String auth) throws CertificateException {
                    throw clientRejection;
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
            X509TrustManager manager = fixture.manager(original, (certificate, result) -> checks.incrementAndGet());
            assertFalse(manager instanceof X509ExtendedTrustManager);
            assertNotSame(original, manager);
            manager.checkServerTrusted(chain(leaf), "RSA");
            assertSame(clientRejection, assertThrows(CertificateException.class, () -> manager.checkClientTrusted(chain(leaf), "RSA")));
            assertEquals(1, checks.get());
        }
    }

    @Test
    void anOpaqueWrapperCannotTriggerPrematureInnerEnforcement() throws Exception {
        try (Fixture fixture = new Fixture()) {
            List<String> events = new ArrayList<>();
            ServerCertificateCheck check = (certificate, result) -> events.add("enforce");
            X509TrustManager original = new X509TrustManager() {
                public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
                    fixture.validate(path(leaf.certificate), parameters());
                }

                public void checkClientTrusted(X509Certificate[] chain, String auth) {}

                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
            X509TrustManager inner = fixture.manager(original, check);
            CertificateException rejection = new CertificateException("opaque post-validation rejection");
            X509TrustManager opaque = new X509TrustManager() {
                public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
                    events.add("before");
                    inner.checkServerTrusted(chain, auth);
                    events.add("after");
                    throw rejection;
                }

                public void checkClientTrusted(X509Certificate[] chain, String auth) {}

                public X509Certificate[] getAcceptedIssuers() {
                    throw new AssertionError("must not reconstruct trust inputs");
                }
            };
            X509TrustManager outer = fixture.manager(opaque, check);
            assertSame(rejection, assertThrows(CertificateException.class, () -> outer.checkServerTrusted(chain(leaf), "RSA")));
            assertEquals(Arrays.asList("before", "after"), events);
        }
    }

    @Test
    void nonX509ManagersAreNotReplacedAndTheProviderArrayIsNotModified() throws Exception {
        try (Providers providers = new Providers(true)) {
            TrustManager original = providers.managers[0];
            providers.owner.add(DelegatingService.checkedTrustManagerFactory(providers.owner, providers.algorithm, providers.algorithm, Collections.singletonList(providers.alias),
                    (certificate, result) -> fail("not an X509 manager")));
            TrustManagerFactory factory = TrustManagerFactory.getInstance(providers.algorithm);
            factory.init((KeyStore) null);
            TrustManager[] wrapped = factory.getTrustManagers();
            assertNotSame(providers.managers, wrapped);
            assertSame(original, wrapped[0]);
            assertSame(original, providers.managers[0]);
        }
    }

    @Test
    void multipleAcceptedIssuerEncodingsAreNotCollapsedToTheLastPath() throws Exception {
        try (Fixture fixture = new Fixture()) {
            CertificateFixture variant = new CertificateFixture(
                    new byte[] {75},
                    false,
                    false,
                    null,
                    issuer.keys,
                    issuer.certificate.getSubjectX500Principal().getName(),
                    issuer.keys);
            PKIXParameters alternate = new PKIXParameters(Collections.singleton(new TrustAnchor(variant.certificate, null)));
            alternate.setRevocationEnabled(false);
            AuthenticatedPaths.verify(
                    chain(leaf),
                    (certificate, result) -> {
                        assertEquals(2, result.paths().size());
                        assertEquals(issuer.certificate,
                                result.paths()
                                      .get(0)
                                      .issuer());
                        assertEquals(variant.certificate,
                                result.paths()
                                      .get(1)
                                      .issuer());
                    },
                    () -> {
                        fixture.validate(path(leaf.certificate), parameters());
                        fixture.validate(path(leaf.certificate), alternate);
                    });
        }
    }

    @Test
    void offThreadValidationLeavesUnavailableEvidenceRatherThanAGuessedIssuer() throws Exception {
        try (Fixture fixture = new Fixture()) {
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                AuthenticatedPaths.verify(
                        chain(leaf),
                        (certificate, result) -> assertTrue(result.paths().isEmpty()),
                        () -> {
                            Future<?> validation = worker.submit(() -> {
                                fixture.validate(path(leaf.certificate), parameters());
                                return null;
                            });
                            assertDoesNotThrow(() -> validation.get(10, TimeUnit.SECONDS));
                        });
            } finally {
                worker.shutdownNow();
            }
        }
    }

    @Test
    void operationScopesRejectOutOfOrderAndRepeatedUse() throws Exception {
        AuthenticatedPaths.verify(
                chain(leaf),
                (certificate, result) -> assertTrue(result.paths().isEmpty()),
                () -> {
                    Operation outer = AuthenticatedPaths.begin();
                    Operation inner = AuthenticatedPaths.begin();
                    assertThrows(IllegalStateException.class, outer::close);
                    inner.close();
                    outer.close();
                    assertThrows(IllegalStateException.class, outer::close);
                    assertThrows(IllegalStateException.class, () -> outer.validated(path(leaf.certificate), null));
                });
    }

    @Test
    void invalidConfigurationAndUnexpectedDelegateFailuresAreNotTurnedIntoEvidence() throws Exception {
        AtomicInteger checks = new AtomicInteger();
        ServerCertificateCheck check = (certificate, result) -> checks.incrementAndGet();
        IllegalStateException failure = new IllegalStateException("unexpected delegate failure");
        assertSame(failure,
                assertThrows(IllegalStateException.class,
                        () -> AuthenticatedPaths.verify(chain(leaf), check, () -> {
                            throw failure;
                        })));
        assertEquals(0, checks.get());
        try (Fixture fixture = new Fixture()) {
            assertThrows(
                    NullPointerException.class,
                    () -> DelegatingService.checkedTrustManagerFactory(fixture.providers.owner, fixture.providers.algorithm, fixture.providers.algorithm, null, null));
        }
    }

    @Test
    void acceptedMalformedInputCannotTurnIntoASuccessfulRevocationCheck() throws Exception {
        AtomicInteger checks = new AtomicInteger();
        ServerCertificateCheck check = (certificate, result) -> checks.incrementAndGet();
        assertThrows(CertificateException.class, () -> AuthenticatedPaths.verify(null, check, () -> {}));
        assertThrows(CertificateException.class,
                () -> AuthenticatedPaths.verify(new X509Certificate[0], check, () -> {}));
        assertEquals(0, checks.get());
        CertificateException rejection = new CertificateException("delegate input validation");
        assertSame(rejection,
                assertThrows(CertificateException.class, () -> AuthenticatedPaths.verify(null, check, () -> {
                    throw rejection;
                })));
    }

    private static PKIXParameters parameters() throws CertificateException {
        try {
            PKIXParameters parameters = new PKIXParameters(Collections.singleton(new TrustAnchor(issuer.certificate, null)));
            parameters.setRevocationEnabled(false);
            return parameters;
        } catch (InvalidAlgorithmParameterException failure) {
            throw new CertificateException(failure);
        }
    }

    private static CertPath path(X509Certificate certificate) throws CertificateException {
        return CertificateFactory.getInstance("X.509").generateCertPath(Collections.singletonList(certificate));
    }

    private static X509Certificate[] chain(CertificateFixture target) {
        return new X509Certificate[] {target.certificate};
    }

    private static final class Fixture implements AutoCloseable {
        final Providers providers = new Providers(true);

        Fixture() {
            providers.owner.add(new DelegatingService(providers.owner, "CertPathValidator", providers.algorithm, "PKIX", null));
            providers.owner.add(new DelegatingService(providers.owner, "CertPathBuilder", providers.algorithm, "PKIX", null));
        }

        void validate(CertPath path, PKIXParameters parameters) throws CertificateException {
            try {
                CertPathValidator.getInstance(providers.algorithm).validate(path, parameters);
            } catch (NoSuchAlgorithmException | CertPathValidatorException | InvalidAlgorithmParameterException failure) {
                throw new CertificateException(failure);
            }
        }

        X509TrustManager manager(X509TrustManager original, ServerCertificateCheck check) throws Exception {
            providers.managers[0] = original;
            providers.owner.add(DelegatingService.checkedTrustManagerFactory(providers.owner, providers.algorithm, providers.algorithm,
                    Collections.singletonList(providers.alias), check));
            TrustManagerFactory factory = TrustManagerFactory.getInstance(providers.algorithm);
            factory.init((KeyStore) null);
            TrustManager[] managers = factory.getTrustManagers();
            assertNotSame(providers.managers, managers);
            assertSame(original, providers.managers[0]);
            return (X509TrustManager) managers[0];
        }

        public void close() {
            providers.close();
        }
    }
}
