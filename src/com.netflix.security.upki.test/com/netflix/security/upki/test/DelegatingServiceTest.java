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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider.Service;
import java.security.ProviderException;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import com.netflix.security.upki.provider.DelegatingService;
import com.netflix.security.upki.provider.InvocationGuard;
import com.netflix.security.upki.test.DelegateFactoryTest.Providers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class DelegatingServiceTest {
    private static final String TRUST = "TrustManagerFactory";
    private static final String VALIDATOR = "CertPathValidator";
    private static final String BUILDER = "CertPathBuilder";

    @ParameterizedTest
    @ValueSource(strings = {TRUST, VALIDATOR, BUILDER})
    void actualAdaptersPreserveFirstOtherWrappers(String type) throws Exception {
        try (Providers providers = new Providers(true)) {
            assertNotNull(instance(type, providers.alias.toLowerCase(Locale.ROOT)));
            assertEquals(Arrays.asList("A", "B", "base"), providers.constructed);
        }
    }

    @Test
    void trustFactoryForwardsBothInitFormsAndOriginalManagerArray() throws Exception {
        try (Providers providers = new Providers(true)) {
            TrustManagerFactory factory = TrustManagerFactory.getInstance(providers.algorithm);
            assertSame(providers.managers, factory.getTrustManagers());
            KeyStore store = KeyStore.getInstance("JKS");
            store.load(null, null);
            factory.init(store);
            assertSame(store, providers.input);
            assertSame(providers.managers, factory.getTrustManagers());
            factory.init((KeyStore) null);
            assertNull(providers.input);
            ManagerFactoryParameters parameters = new ManagerFactoryParameters() {};
            factory.init(parameters);
            assertSame(parameters, providers.input);
            assertEquals(
                    Arrays.asList("A.store", "B.store", "base.store", "A.store", "B.store", "base.store",
                            "A.parameters", "B.parameters", "base.parameters"),
                    providers.calls);
        }
    }

    @Test
    void validatorForwardsOriginalObjectsResultAndChecker() throws Exception {
        try (Providers providers = new Providers(true)) {
            CertPathValidator validator = CertPathValidator.getInstance(providers.alias);
            CertPath path = path();
            CertPathParameters parameters = new Parameters();
            assertSame(providers.validation, validator.validate(path, parameters));
            assertSame(path, providers.path);
            assertSame(parameters, providers.input);
            assertSame(providers.checker, validator.getRevocationChecker());
            assertEquals(Arrays.asList("A.validate", "B.validate", "base.validate"), providers.calls);
        }
    }

    @Test
    void builderForwardsOriginalParametersResultAndChecker() throws Exception {
        try (Providers providers = new Providers(true)) {
            CertPathBuilder builder = CertPathBuilder.getInstance(providers.algorithm);
            CertPathParameters parameters = new Parameters();
            assertSame(providers.building, builder.build(parameters));
            assertSame(parameters, providers.input);
            assertSame(providers.checker, builder.getRevocationChecker());
            assertEquals(Arrays.asList("A.build", "B.build", "base.build"), providers.calls);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {TRUST, VALIDATOR, BUILDER})
    void unpinnedLookupCannotSilentlySkipAConstructionFailure(String type) throws Exception {
        try (Providers providers = new Providers(true)) {
            NoSuchAlgorithmException rejection = new NoSuchAlgorithmException("wrapper could not construct");
            providers.constructionFailure = rejection;
            ProviderException failure = assertThrows(ProviderException.class, () -> instance(type, providers.algorithm));
            assertSame(rejection, failure.getCause());
            assertEquals(Collections.singletonList("A"), providers.constructed);
            providers.constructionFailure = null;
            providers.constructed.clear();
            assertNotNull(instance(type, providers.algorithm));
            assertEquals(Arrays.asList("A", "B", "base"), providers.constructed);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {TRUST, VALIDATOR, BUILDER})
    void missingDelegateIsAnExplicitProviderFailure(String type) throws Exception {
        try (Providers providers = new Providers(true)) {
            Security.removeProvider(providers.a.getName());
            Security.removeProvider(providers.b.getName());
            Security.removeProvider(providers.base.getName());
            ProviderException failure = assertThrows(ProviderException.class, () -> instance(type, providers.algorithm));
            assertInstanceOf(NoSuchAlgorithmException.class, failure.getCause());
            assertTrue(failure.getMessage().contains(type));
        }
    }

    @Test
    void trustFactoryPreservesCheckedRejectionsAndCanBeReinitialized() throws Exception {
        try (Providers providers = new Providers(true)) {
            TrustManagerFactory factory = TrustManagerFactory.getInstance(providers.algorithm);
            providers.storeFailure = new KeyStoreException("store policy rejected");
            assertSame(providers.storeFailure, assertThrows(KeyStoreException.class, () -> factory.init((KeyStore) null)));
            providers.storeFailure = null;
            providers.parameterFailure = new InvalidAlgorithmParameterException("parameter policy rejected");
            assertSame(providers.parameterFailure, assertThrows(InvalidAlgorithmParameterException.class, () -> factory.init(new ManagerFactoryParameters() {})));
            providers.parameterFailure = null;
            factory.init((KeyStore) null);
            assertSame(providers.managers, factory.getTrustManagers());
        }
    }

    @Test
    void validatorPreservesCheckedAndUncheckedRejections() throws Exception {
        try (Providers providers = new Providers(true)) {
            CertPathValidator validator = CertPathValidator.getInstance(providers.algorithm);
            CertPath path = path();
            providers.validationFailure = new CertPathValidatorException("policy rejected");
            assertSame(providers.validationFailure, assertThrows(CertPathValidatorException.class, () -> validator.validate(path, new Parameters())));
            providers.validationFailure = null;
            providers.parameterFailure = new InvalidAlgorithmParameterException("invalid parameters");
            assertSame(providers.parameterFailure, assertThrows(InvalidAlgorithmParameterException.class, () -> validator.validate(path, new Parameters())));
            providers.parameterFailure = null;
            providers.checkerFailure = new ProviderException("checker failed");
            assertSame(providers.checkerFailure, assertThrows(ProviderException.class, validator::getRevocationChecker));
            providers.checkerFailure = null;
            assertSame(providers.validation, validator.validate(path, new Parameters()));
        }
    }

    @Test
    void builderPreservesCheckedAndUncheckedRejections() throws Exception {
        try (Providers providers = new Providers(true)) {
            CertPathBuilder builder = CertPathBuilder.getInstance(providers.algorithm);
            providers.buildingFailure = new CertPathBuilderException("policy rejected");
            assertSame(providers.buildingFailure, assertThrows(CertPathBuilderException.class, () -> builder.build(new Parameters())));
            providers.buildingFailure = null;
            providers.parameterFailure = new InvalidAlgorithmParameterException("invalid parameters");
            assertSame(providers.parameterFailure, assertThrows(InvalidAlgorithmParameterException.class, () -> builder.build(new Parameters())));
            providers.parameterFailure = null;
            providers.checkerFailure = new ProviderException("checker failed");
            assertSame(providers.checkerFailure, assertThrows(ProviderException.class, builder::getRevocationChecker));
            providers.checkerFailure = null;
            assertSame(providers.building, builder.build(new Parameters()));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"store", "parameters", "managers", "validate", "build", "validator-checker",
                "builder-checker"})
    void delayedSelectionCycleFailsWithABoundedProviderErrorAndNoSkippedWrapper(String operation) throws Exception {
        try (Providers providers = new Providers(true)) {
            providers.delayedOperation = operation.endsWith("checker") ? "checker" : operation;
            ProviderException failure = assertThrows(ProviderException.class, () -> invoke(providers, operation));
            assertTrue(failure.getMessage().contains("delegation"),
                    failure.getMessage());
            assertFalse(providers.constructed.isEmpty());
            assertTrue(providers.constructed.size() <= 64, "cycle was not bounded");
            assertTrue(providers.constructed.stream()
                                .allMatch("A"::equals),
                    "policy wrapper was bypassed");
            providers.delayedOperation = null;
            providers.constructed.clear();
            invoke(providers, operation);
            assertEquals(Arrays.asList("A", "B", "base"), providers.constructed);
        }
    }

    @Test
    void independentNestedValidationUsesTheSameProvidersRatherThanSkippingThem() throws Exception {
        try (Providers providers = new Providers(true)) {
            providers.independentValidation = true;
            CertPathValidator validator = CertPathValidator.getInstance(providers.algorithm);
            assertSame(providers.validation,
                    validator.validate(path(), new Parameters()));
            assertEquals(Arrays.asList("A.validate", "B.validate", "base.validate", "A.validate", "B.validate", "base.validate"), providers.calls);
            assertEquals(Arrays.asList("A", "B", "base", "A", "B", "base"), providers.constructed);
        }
    }

    @Test
    void invocationLimitIsThreadLocalAndAnExceededLimitDoesNotCorruptTheStack() throws Exception {
        try (Providers providers = new Providers(true)) {
            CertPathValidator validator = CertPathValidator.getInstance(providers.algorithm);
            ExecutorService worker = Executors.newSingleThreadExecutor();
            List<InvocationGuard> guards = new ArrayList<>();
            try {
                for (int i = 0; i < 32; i++) {
                    guards.add(InvocationGuard.enter());
                }
                assertThrows(ProviderException.class, validator::getRevocationChecker);
                assertSame(providers.checker, worker.submit(validator::getRevocationChecker)
                        .get(10, TimeUnit.SECONDS));
            } finally {
                for (int i = guards.size() - 1; i >= 0; i--) {
                    guards.get(i).close();
                }
                worker.shutdownNow();
            }
            assertSame(providers.checker, validator.getRevocationChecker());
        }
    }

    @Test
    void invocationGuardsRejectWrongOrderAndDoubleCloseWithoutChangingTheActiveScope() {
        InvocationGuard outer = InvocationGuard.enter();
        try {
            InvocationGuard inner = InvocationGuard.enter();
            try {
                assertThrows(IllegalStateException.class, outer::close);
            } finally {
                inner.close();
            }
        } finally {
            outer.close();
        }
        assertThrows(IllegalStateException.class, outer::close);
    }

    @Test
    void invocationGuardCannotBeClosedByAnotherThread() throws Exception {
        InvocationGuard guard = InvocationGuard.enter();
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            worker.submit(() -> assertThrows(IllegalStateException.class, guard::close)).get(10, TimeUnit.SECONDS);
        } finally {
            worker.shutdownNow();
            guard.close();
        }
    }

    @Test
    void explicitAlgorithmCanDelegateToTheExistingPkixAlgorithm() throws Exception {
        try (Providers providers = new Providers(true)) {
            String explicit = providers.algorithm + "-explicit";
            providers.owner.add(new DelegatingService(providers.owner, TRUST, explicit, providers.algorithm, Collections.emptyList()));
            TrustManagerFactory factory = TrustManagerFactory.getInstance(explicit);
            assertEquals(explicit, factory.getAlgorithm());
            factory.init((KeyStore) null);
            assertSame(providers.managers, factory.getTrustManagers());
            assertEquals(Arrays.asList("A", "B", "base"), providers.constructed);
        }
    }

    @Test
    void serviceRejectsUnexpectedParametersAndUnsupportedTypes() throws Exception {
        try (Providers providers = new Providers(true)) {
            Service service = providers.owner.getService(VALIDATOR, providers.algorithm);
            assertThrows(InvalidParameterException.class, () -> service.newInstance(new Object()));
            assertThrows(IllegalArgumentException.class, () -> new DelegatingService(providers.owner, "Signature", "PKIX", "PKIX", Collections.emptyList()));
            assertThrows(NullPointerException.class, () -> new DelegatingService(providers.owner, VALIDATOR, "PKIX", null, Collections.emptyList()));
        }
    }

    @Test
    void spiImplementationPackagesRemainUnexportedInTheNamedModule() {
        Module module = DelegatingService.class.getModule();
        assertTrue(module.isNamed());
        assertFalse(module.isExported("com.netflix.security.ssl", getClass().getModule()));
        assertFalse(module.isExported("com.netflix.security.provider.certpath", getClass().getModule()));
    }

    @Test
    void adaptersDelegateToRealJdkPkixWithoutHardCodedProviders() throws Exception {
        try (Providers providers = new Providers(true)) {
            String algorithm = providers.algorithm + "-real";
            for (String type : Arrays.asList(TRUST, VALIDATOR, BUILDER)) {
                providers.owner.add(new DelegatingService(providers.owner, type, algorithm, "PKIX", Collections.emptyList()));
            }
            CertificateFixture issuer = new CertificateFixture(new byte[] {40}, false, true, null);
            CertificateFixture leaf = new CertificateFixture(new byte[] {41}, true, true, null, issuer.keys,
                    "CN=localhost");
            KeyStore roots = KeyStore.getInstance("JKS");
            roots.load(null, null);
            roots.setCertificateEntry("issuer", issuer.certificate);
            TrustManagerFactory factory = TrustManagerFactory.getInstance(algorithm);
            assertThrows(IllegalStateException.class, factory::getTrustManagers);
            factory.init(roots);
            ((X509TrustManager) factory.getTrustManagers()[0]).checkServerTrusted(new X509Certificate[] {leaf.certificate, issuer.certificate}, "RSA");
            CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(Collections.singletonList(leaf.certificate));
            PKIXParameters parameters = new PKIXParameters(roots);
            parameters.setRevocationEnabled(false);
            CertPathValidator validator = CertPathValidator.getInstance(algorithm);
            PKIXCertPathValidatorResult validated = (PKIXCertPathValidatorResult) validator.validate(path, parameters);
            assertEquals(issuer.certificate, validated.getTrustAnchor().getTrustedCert());
            assertInstanceOf(PKIXRevocationChecker.class, validator.getRevocationChecker());
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(leaf.certificate);
            PKIXBuilderParameters building = new PKIXBuilderParameters(roots, target);
            building.setRevocationEnabled(false);
            building.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(Arrays.asList(leaf.certificate, issuer.certificate))));
            CertPathBuilder builder = CertPathBuilder.getInstance(algorithm);
            PKIXCertPathBuilderResult built = (PKIXCertPathBuilderResult) builder.build(building);
            assertEquals(issuer.certificate, built.getTrustAnchor().getTrustedCert());
            assertInstanceOf(PKIXRevocationChecker.class, builder.getRevocationChecker());
            factory.init(new CertPathTrustManagerParameters(building));
            ((X509TrustManager) factory.getTrustManagers()[0]).checkServerTrusted(new X509Certificate[] {leaf.certificate}, "RSA");
        }
    }

    @Test
    void realPkixRegistrationPreservesTlsAndHostnameRejectionInAnIsolatedJvm(@TempDir Path directory) throws Exception {
        String executable = System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java";
        Path java = Paths.get(System.getProperty("java.home"), "bin", executable);
        Set<String> locations = new LinkedHashSet<>();
        // Incremental module compilation can give these classes different code sources.
        for (String name : Arrays.asList(
                DelegatingService.class.getName(),
                InvocationGuard.class.getName(),
                DelegatingTlsProbe.class.getName(),
                CertificateFixture.class.getName(),
                CacheFixture.class.getName(),
                "com.netflix.security.upki.checker.AuthenticatedPaths",
                "com.netflix.security.upki.checker.ServerCertificateCheck",
                "com.netflix.security.upki.checker.CacheChecker",
                "com.netflix.security.upki.checker.CheckPolicy",
                "com.netflix.security.upki.checker.CheckDiagnostics",
                "com.netflix.security.upki.checker.RevocationEnforcer",
                "com.netflix.security.upki.checker.CertificateInputs",
                "com.netflix.security.upki.checker.RevocationInput",
                "com.netflix.security.upki.cache.CacheDiscovery",
                "com.netflix.security.upki.cache.CachePaths",
                "com.netflix.security.upki.cache.RevocationIndex",
                "com.netflix.security.upki.clubcard.Clubcard",
                "com.netflix.security.upki.clubcard.ClubcardReader",
                "com.netflix.security.ssl.ServerTrustManager",
                "com.netflix.security.upki.provider.DelegateFactory",
                "com.netflix.security.provider.certpath.DelegatingCertPathValidator",
                "com.netflix.security.provider.certpath.DelegatingCertPathBuilder",
                "com.netflix.security.ssl.DelegatingTrustManagerFactory")) {
            for (Class<?> type : Class.forName(name).getNestMembers()) {
                locations.add(Paths.get(type.getProtectionDomain()
                                            .getCodeSource()
                                            .getLocation()
                                            .toURI())
                        .toString());
            }
        }
        String classpath = String.join(File.pathSeparator, locations);
        Path output = directory.resolve("tls-spi.log");
        Process process = new ProcessBuilder(java.toString(), "-cp", classpath, DelegatingTlsProbe.class.getName())
                .redirectErrorStream(true)
                .redirectOutput(output.toFile())
                .start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly().waitFor();
            fail("SPI/TLS probe timed out: " + output);
        }
        String report = new String(Files.readAllBytes(output), StandardCharsets.UTF_8);
        assertEquals(0, process.exitValue(), report);
        assertTrue(report.contains("PASS SPI adapters and TLS"), report);
    }

    private static Object instance(String type, String algorithm) throws NoSuchAlgorithmException {
        switch (type) {
            case TRUST:
                return TrustManagerFactory.getInstance(algorithm);
            case VALIDATOR:
                return CertPathValidator.getInstance(algorithm);
            case BUILDER:
                return CertPathBuilder.getInstance(algorithm);
            default:
                throw new AssertionError(type);
        }
    }

    private static void invoke(Providers providers, String operation) throws Exception {
        switch (operation) {
            case "store":
                TrustManagerFactory.getInstance(providers.algorithm).init((KeyStore) null);
                break;
            case "parameters":
                TrustManagerFactory.getInstance(providers.algorithm).init(new ManagerFactoryParameters() {});
                break;
            case "managers":
                {
                    TrustManagerFactory factory = TrustManagerFactory.getInstance(providers.algorithm);
                    factory.init((KeyStore) null);
                    assertSame(providers.managers, factory.getTrustManagers());
                    break;
                }
            case "validate":
                assertSame(providers.validation,
                        CertPathValidator.getInstance(providers.algorithm).validate(path(), new Parameters()));
                break;
            case "build":
                assertSame(providers.building, CertPathBuilder.getInstance(providers.algorithm)
                        .build(new Parameters()));
                break;
            case "validator-checker":
                assertSame(providers.checker, CertPathValidator.getInstance(providers.algorithm)
                        .getRevocationChecker());
                break;
            case "builder-checker":
                assertSame(providers.checker, CertPathBuilder.getInstance(providers.algorithm)
                        .getRevocationChecker());
                break;
            default:
                throw new AssertionError(operation);
        }
    }

    private static CertPath path() throws Exception {
        return CertificateFactory.getInstance("X.509").generateCertPath(Collections.emptyList());
    }

    private static final class Parameters implements CertPathParameters {
        public Object clone() {
            return this;
        }
    }
}
