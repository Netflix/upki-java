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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.ProviderException;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathChecker;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;

import com.netflix.security.upki.provider.DelegateFactory;
import com.netflix.security.upki.provider.DelegatingService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DelegateFactoryTest {
    private static final String VALIDATOR = "CertPathValidator";
    private static final String BUILDER = "CertPathBuilder";
    private static final String TRUST = "TrustManagerFactory";
    private static final AtomicInteger IDS = new AtomicInteger();

    @ParameterizedTest
    @ValueSource(strings = {TRUST, VALIDATOR, BUILDER})
    void preservesTwoFirstOtherWrappersWithoutAConstructionCycle(String type) throws Exception {
        try (Providers providers = new Providers()) {
            Object instance = instance(type, providers.algorithm, providers.owner);
            assertNotNull(instance);
            assertEquals(Arrays.asList("A", "B", "base"), providers.constructed);
        }
    }

    @Test
    void aliasesAndCaseCannotEvadeCycleDetection() throws Exception {
        try (Providers providers = new Providers()) {
            instance(VALIDATOR, providers.alias.toLowerCase(Locale.ROOT), providers.owner);
            assertEquals(Arrays.asList("A", "B", "base"), providers.constructed);
        }
    }

    @Test
    void trustFactoryPreservesBothInitFormsAndResultIdentity() throws Exception {
        try (Providers providers = new Providers()) {
            TrustManagerFactory factory = (TrustManagerFactory) instance(TRUST, providers.algorithm, providers.owner);
            KeyStore store = KeyStore.getInstance("JKS");
            store.load(null, null);
            factory.init(store);
            assertSame(store, providers.input);
            assertEquals(Arrays.asList("A.store", "B.store", "base.store"), providers.calls);
            assertSame(providers.managers, factory.getTrustManagers());
            providers.calls.clear();
            factory.init((KeyStore) null);
            assertNull(providers.input);
            ManagerFactoryParameters parameters = new ManagerFactoryParameters() {};
            factory.init(parameters);
            assertSame(parameters, providers.input);
            assertEquals(Arrays.asList("A.store", "B.store", "base.store", "A.parameters", "B.parameters", "base.parameters"), providers.calls);
        }
    }

    @Test
    void validatorPreservesInputsResultsAndChecker() throws Exception {
        try (Providers providers = new Providers()) {
            CertPathValidator validator = (CertPathValidator) instance(VALIDATOR, providers.algorithm, providers.owner);
            CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(Collections.emptyList());
            CertPathParameters parameters = new Parameters();
            assertSame(providers.validation, validator.validate(path, parameters));
            assertSame(path, providers.path);
            assertSame(parameters, providers.input);
            assertEquals(Arrays.asList("A.validate", "B.validate", "base.validate"), providers.calls);
            assertSame(providers.checker, validator.getRevocationChecker());
        }
    }

    @Test
    void builderPreservesParametersResultsAndChecker() throws Exception {
        try (Providers providers = new Providers()) {
            CertPathBuilder builder = (CertPathBuilder) instance(BUILDER, providers.algorithm, providers.owner);
            CertPathParameters parameters = new Parameters();
            assertSame(providers.building, builder.build(parameters));
            assertSame(parameters, providers.input);
            assertEquals(Arrays.asList("A.build", "B.build", "base.build"), providers.calls);
            assertSame(providers.checker, builder.getRevocationChecker());
        }
    }

    @Test
    void validatorRejectionIsNotChangedOrRetried() throws Exception {
        try (Providers providers = new Providers()) {
            CertPathValidator validator = (CertPathValidator) instance(VALIDATOR, providers.algorithm, providers.owner);
            CertPathValidatorException rejection = new CertPathValidatorException("wrapper policy rejected");
            providers.validationFailure = rejection;
            CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(Collections.emptyList());
            assertSame(rejection, assertThrows(CertPathValidatorException.class, () -> validator.validate(path, new Parameters())));
            assertEquals(Arrays.asList("A.validate"), providers.calls);
        }
    }

    @Test
    void constructionFailureDoesNotSkipTheSelectedWrapperAndCleansUpState() throws Exception {
        try (Providers providers = new Providers()) {
            NoSuchAlgorithmException rejection = new NoSuchAlgorithmException("selected wrapper unavailable");
            providers.constructionFailure = rejection;
            assertSame(rejection,
                    assertThrows(NoSuchAlgorithmException.class, () -> DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm, provider -> CertPathValidator.getInstance(providers.algorithm, provider))));
            assertEquals(Collections.singletonList("A"), providers.constructed);
            providers.constructionFailure = null;
            providers.constructed.clear();
            instance(VALIDATOR, providers.algorithm, providers.owner);
            assertEquals(Arrays.asList("A", "B", "base"), providers.constructed);
        }
    }

    @Test
    void uncheckedFailureIsNotSwallowedAndCleansUpState() throws Exception {
        try (Providers providers = new Providers()) {
            ProviderException failure = new ProviderException("provider defect");
            assertSame(failure,
                    assertThrows(ProviderException.class, () -> DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm, provider -> {
                        throw failure;
                    })));
            instance(VALIDATOR, providers.algorithm, providers.owner);
            assertEquals(Arrays.asList("A", "B", "base"), providers.constructed);
        }
    }

    @Test
    void missingDelegateFailsWithoutRecursing() throws Exception {
        try (Providers providers = new Providers()) {
            Security.removeProvider(providers.a.getName());
            Security.removeProvider(providers.b.getName());
            Security.removeProvider(providers.base.getName());
            NoSuchAlgorithmException failure = assertThrows(NoSuchAlgorithmException.class, () -> DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm, provider -> CertPathValidator.getInstance(providers.algorithm, provider)));
            assertTrue(failure.getMessage().contains(providers.algorithm));
        }
    }

    @Test
    void exhaustedConstructionRouteFailsAndRestoresState() throws Exception {
        try (Providers providers = new Providers()) {
            Security.removeProvider(providers.base.getName());
            assertThrows(NoSuchAlgorithmException.class, () -> instance(VALIDATOR, providers.algorithm, providers.owner));
            assertEquals(Arrays.asList("A", "B"), providers.constructed);
            Security.addProvider(providers.base);
            providers.constructed.clear();
            instance(VALIDATOR, providers.algorithm, providers.owner);
            assertEquals(Arrays.asList("A", "B", "base"), providers.constructed);
        }
    }

    @Test
    void caughtInnerFailureRestoresTheStillActiveOuterRoute() throws Exception {
        try (Providers providers = new Providers()) {
            DelegateFactory.create(
                    providers.owner,
                    VALIDATOR,
                    providers.algorithm,
                    outer -> {
                        assertSame(providers.a, outer);
                        NoSuchAlgorithmException rejection = new NoSuchAlgorithmException("inner construction rejected");
                        assertSame(rejection,
                                assertThrows(
                                        NoSuchAlgorithmException.class,
                                        () -> DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm,
                                                inner -> {
                                                    assertSame(providers.b, inner);
                                                    throw rejection;
                                                })));
                        return DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm,
                                inner -> {
                                    assertSame(providers.b, inner);
                                    return inner;
                                });
                    });
            assertSame(providers.a, DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm, provider -> provider));
        }
    }

    @Test
    void canonicalNameAndAliasShareAnActiveRoute() throws Exception {
        try (Providers providers = new Providers()) {
            DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm,
                    outer -> {
                        assertSame(providers.a, outer);
                        return DelegateFactory.create(providers.owner, VALIDATOR, providers.alias,
                                inner -> {
                                    assertSame(providers.b, inner);
                                    return inner;
                                });
                    });
        }
    }

    @Test
    void constructionStateIsNotRetainedByTheReturnedDelegate() throws Exception {
        try (Providers providers = new Providers()) {
            Callable<Provider> later = DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm,
                    outer -> () -> DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm, provider -> provider));
            assertSame(providers.a, later.call());
        }
    }

    @Test
    void errorsRestoreStateWithoutBeingSwallowed() throws Exception {
        try (Providers providers = new Providers()) {
            AssertionError failure = new AssertionError("provider error");
            assertSame(failure,
                    assertThrows(AssertionError.class, () -> DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm, provider -> {
                        throw failure;
                    })));
            assertSame(providers.a, DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm, provider -> provider));
        }
    }

    @Test
    void nullArgumentsAndDelegateAreProgrammingErrors() throws Exception {
        try (Providers providers = new Providers()) {
            assertThrows(NullPointerException.class, () -> DelegateFactory.create(null, VALIDATOR, providers.algorithm, provider -> provider));
            assertThrows(NullPointerException.class, () -> DelegateFactory.create(providers.owner, null, providers.algorithm, provider -> provider));
            assertThrows(NullPointerException.class, () -> DelegateFactory.create(providers.owner, VALIDATOR, null, provider -> provider));
            assertThrows(NullPointerException.class, () -> DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm, null));
            assertThrows(NullPointerException.class, () -> DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm, provider -> null));
            assertSame(providers.a, DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm, provider -> provider));
        }
    }

    @Test
    void routingIsScopedByServiceTypeRatherThanWholeProvider() throws Exception {
        try (Providers providers = new Providers()) {
            Object result = DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm,
                    outer -> {
                        assertSame(providers.a, outer);
                        return DelegateFactory.create(providers.owner, BUILDER, providers.algorithm,
                                inner -> {
                                    assertSame(providers.a, inner);
                                    return inner;
                                });
                    });
            assertSame(providers.a, result);
        }
    }

    @Test
    void routingIsScopedByCanonicalAlgorithmRatherThanWholeProvider() throws Exception {
        try (Providers providers = new Providers()) {
            providers.a.add(VALIDATOR, providers.algorithm + "-other", Collections.emptyList(),
                    () -> new Validator(providers, "base", null));
            DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm,
                    outer -> {
                        assertSame(providers.a, outer);
                        return DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm + "-other",
                                inner -> {
                                    assertSame(providers.a, inner);
                                    return inner;
                                });
                    });
        }
    }

    @Test
    void providerOrderIsReadForEachNewAcquisition() throws Exception {
        try (Providers providers = new Providers()) {
            assertSame(providers.a, DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm, provider -> provider));
            Security.removeProvider(providers.a.getName());
            assertSame(providers.b, DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm, provider -> provider));
        }
    }

    @Test
    void constructionScopesDoNotLeakAcrossThreads() throws Exception {
        try (Providers providers = new Providers()) {
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                Provider selected = DelegateFactory.create(
                        providers.owner,
                        VALIDATOR,
                        providers.algorithm,
                        outer -> {
                            Callable<Provider> nested = () -> DelegateFactory.create(providers.owner, VALIDATOR, providers.algorithm, provider -> provider);
                            Future<Provider> result = worker.submit(nested);
                            assertSame(providers.a, assertDoesNotThrow(() -> result.get(10, TimeUnit.SECONDS)));
                            return outer;
                        });
                assertSame(providers.a, selected);
            } finally {
                worker.shutdownNow();
            }
        }
    }

    private static Object instance(String type, String algorithm, Provider provider) throws NoSuchAlgorithmException {
        switch (type) {
            case TRUST:
                return TrustManagerFactory.getInstance(algorithm, provider);
            case VALIDATOR:
                return CertPathValidator.getInstance(algorithm, provider);
            case BUILDER:
                return CertPathBuilder.getInstance(algorithm, provider);
            default:
                throw new AssertionError(type);
        }
    }

    private static Object firstOther(Provider owner, String type, String algorithm) throws NoSuchAlgorithmException {
        for (Provider provider : Security.getProviders()) {
            if (provider != owner && provider.getService(type, algorithm) != null) {
                return instance(type, algorithm, provider);
            }
        }
        throw new NoSuchAlgorithmException(algorithm);
    }

    static final class Providers implements AutoCloseable {
        final String algorithm = "UPKITestRoute-" + IDS.incrementAndGet();
        final String alias = algorithm + "-alias";
        final TestProvider owner = new TestProvider(algorithm + "-owner");
        final TestProvider a = new TestProvider(algorithm + "-A");
        final TestProvider b = new TestProvider(algorithm + "-B");
        final TestProvider base = new TestProvider(algorithm + "-base");
        final List<String> constructed = new ArrayList<>();
        final List<String> calls = new ArrayList<>();
        final TrustManager[] managers = new TrustManager[] {new TrustManager() {}};
        final CertPathValidatorResult validation = new CertPathValidatorResult() {
            public Object clone() {
                return this;
            }
        };
        final CertPathBuilderResult building = new CertPathBuilderResult() {
            public CertPath getCertPath() {
                return path;
            }

            public Object clone() {
                return this;
            }
        };
        final CertPathChecker checker = new CertPathChecker() {
            public void init(boolean forward) {}

            public boolean isForwardCheckingSupported() {
                return false;
            }

            public void check(Certificate certificate) {}
        };
        Object input;
        CertPath path;
        NoSuchAlgorithmException constructionFailure;
        CertPathValidatorException validationFailure;
        CertPathBuilderException buildingFailure;
        KeyStoreException storeFailure;
        InvalidAlgorithmParameterException parameterFailure;
        ProviderException checkerFailure;
        String delayedOperation;
        boolean independentValidation;
        boolean insideIndependentValidation;

        Providers() {
            this(false);
        }

        Providers(boolean adapters) {
            for (String type : Arrays.asList(TRUST, VALIDATOR, BUILDER)) {
                for (TestProvider provider : Arrays.asList(owner, a, b, base)) {
                    if (provider == owner && adapters) {
                        owner.add(new DelegatingService(owner, type, algorithm, algorithm, Collections.singletonList(alias)));
                        continue;
                    }
                    String label = provider == owner
                            ? "owner"
                            : provider == a
                                    ? "A"
                                    : provider == b ? "B" : "base";
                    provider.add(type, algorithm, Collections.singletonList(alias),
                            () -> {
                                Object delegate = null;
                                if (provider == owner) {
                                    delegate = DelegateFactory.create(owner, type, algorithm,
                                            selected -> instance(type, alias.toLowerCase(Locale.ROOT), selected));
                                } else {
                                    constructed.add(label);
                                    if (provider == a && constructionFailure != null) {
                                        throw constructionFailure;
                                    }
                                    if (provider != base && !(provider == a && delayedOperation != null)) {
                                        delegate = firstOther(provider, type, alias);
                                    }
                                }
                                switch (type) {
                                    case TRUST:
                                        return new TrustFactory(this, label, (TrustManagerFactory) delegate);
                                    case VALIDATOR:
                                        return new Validator(this, label, (CertPathValidator) delegate);
                                    case BUILDER:
                                        return new Builder(this, label, (CertPathBuilder) delegate);
                                    default:
                                        throw new AssertionError(type);
                                }
                            });
                }
            }
            assertEquals(1, Security.insertProviderAt(base, 1));
            assertEquals(1, Security.insertProviderAt(b, 1));
            assertEquals(1, Security.insertProviderAt(a, 1));
            assertEquals(1, Security.insertProviderAt(owner, 1));
        }

        public void close() {
            for (Provider provider : Arrays.asList(owner, a, b, base)) {
                Security.removeProvider(provider.getName());
            }
        }

        Object deferred(String label, String operation, String type) {
            if (!label.equals("A") || !operation.equals(delayedOperation)) {
                return null;
            }
            try {
                return firstOther(a, type, alias);
            } catch (NoSuchAlgorithmException failure) {
                throw new ProviderException(failure);
            }
        }

        void call(String label, String operation) {
            if (!label.equals("owner")) {
                calls.add(label + "." + operation);
            }
        }
    }

    static final class TestProvider extends Provider {
        TestProvider(String name) {
            super(name, 1.0, "Isolated delegate-routing test services");
        }

        void add(Service service) {
            putService(service);
        }

        void add(String type, String algorithm, List<String> aliases,
                 Creator creator) {
            putService(new Service(this, type, algorithm, TestProvider.class.getName(), aliases,
                    Collections.emptyMap()) {
                public Object newInstance(Object parameter) throws NoSuchAlgorithmException {
                    assertNull(parameter);
                    return creator.create();
                }
            });
        }
    }

    private interface Creator {
        Object create() throws NoSuchAlgorithmException;
    }

    private static final class Parameters implements CertPathParameters {
        public Object clone() {
            return this;
        }
    }

    private static final class TrustFactory extends TrustManagerFactorySpi {
        final Providers providers;
        final String label;
        final TrustManagerFactory delegate;

        TrustFactory(Providers providers, String label, TrustManagerFactory delegate) {
            this.providers = providers;
            this.label = label;
            this.delegate = delegate;
        }

        protected void engineInit(KeyStore store) throws KeyStoreException {
            providers.call(label, "store");
            if (label.equals("A") && providers.storeFailure != null) {
                throw providers.storeFailure;
            }
            TrustManagerFactory deferred = (TrustManagerFactory) providers.deferred(label, "store", TRUST);
            if (deferred != null) {
                deferred.init(store);
                return;
            }
            if (delegate != null) {
                delegate.init(store);
            } else {
                providers.input = store;
            }
        }

        protected void engineInit(ManagerFactoryParameters parameters) throws InvalidAlgorithmParameterException {
            providers.call(label, "parameters");
            if (label.equals("A") && providers.parameterFailure != null) {
                throw providers.parameterFailure;
            }
            TrustManagerFactory deferred = (TrustManagerFactory) providers.deferred(label, "parameters", TRUST);
            if (deferred != null) {
                deferred.init(parameters);
                return;
            }
            if (delegate != null) {
                delegate.init(parameters);
            } else {
                providers.input = parameters;
            }
        }

        protected TrustManager[] engineGetTrustManagers() {
            TrustManagerFactory deferred = (TrustManagerFactory) providers.deferred(label, "managers", TRUST);
            if (deferred != null) {
                try {
                    deferred.init((KeyStore) null);
                } catch (KeyStoreException failure) {
                    throw new ProviderException(failure);
                }
                return deferred.getTrustManagers();
            }
            return delegate == null ? providers.managers : delegate.getTrustManagers();
        }
    }

    private static final class Validator extends CertPathValidatorSpi {
        final Providers providers;
        final String label;
        final CertPathValidator delegate;

        Validator(Providers providers, String label, CertPathValidator delegate) {
            this.providers = providers;
            this.label = label;
            this.delegate = delegate;
        }

        public CertPathValidatorResult engineValidate(CertPath path, CertPathParameters parameters) throws CertPathValidatorException, InvalidAlgorithmParameterException {
            providers.call(label, "validate");
            if (label.equals("A") && providers.validationFailure != null) {
                throw providers.validationFailure;
            }
            if (label.equals("A") && providers.parameterFailure != null) {
                throw providers.parameterFailure;
            }
            CertPathValidator deferred = (CertPathValidator) providers.deferred(label, "validate", VALIDATOR);
            if (deferred != null) {
                return deferred.validate(path, parameters);
            }
            if (delegate != null) {
                return delegate.validate(path, parameters);
            }
            if (providers.independentValidation && !providers.insideIndependentValidation) {
                providers.insideIndependentValidation = true;
                try {
                    CertPathValidator nested = (CertPathValidator) instance(VALIDATOR, providers.alias, providers.owner);
                    assertSame(providers.validation, nested.validate(path, parameters));
                } catch (NoSuchAlgorithmException failure) {
                    throw new AssertionError(failure);
                } finally {
                    providers.insideIndependentValidation = false;
                }
            }
            providers.path = path;
            providers.input = parameters;
            return providers.validation;
        }

        public CertPathChecker engineGetRevocationChecker() {
            if (label.equals("A") && providers.checkerFailure != null) {
                throw providers.checkerFailure;
            }
            CertPathValidator deferred = (CertPathValidator) providers.deferred(label, "checker", VALIDATOR);
            if (deferred != null) {
                return deferred.getRevocationChecker();
            }
            return delegate == null ? providers.checker : delegate.getRevocationChecker();
        }
    }

    private static final class Builder extends CertPathBuilderSpi {
        final Providers providers;
        final String label;
        final CertPathBuilder delegate;

        Builder(Providers providers, String label, CertPathBuilder delegate) {
            this.providers = providers;
            this.label = label;
            this.delegate = delegate;
        }

        public CertPathBuilderResult engineBuild(CertPathParameters parameters) throws CertPathBuilderException, InvalidAlgorithmParameterException {
            providers.call(label, "build");
            if (label.equals("A") && providers.buildingFailure != null) {
                throw providers.buildingFailure;
            }
            if (label.equals("A") && providers.parameterFailure != null) {
                throw providers.parameterFailure;
            }
            CertPathBuilder deferred = (CertPathBuilder) providers.deferred(label, "build", BUILDER);
            if (deferred != null) {
                return deferred.build(parameters);
            }
            if (delegate != null) {
                return delegate.build(parameters);
            }
            providers.input = parameters;
            return providers.building;
        }

        public CertPathChecker engineGetRevocationChecker() {
            if (label.equals("A") && providers.checkerFailure != null) {
                throw providers.checkerFailure;
            }
            CertPathBuilder deferred = (CertPathBuilder) providers.deferred(label, "checker", BUILDER);
            if (deferred != null) {
                return deferred.getRevocationChecker();
            }
            return delegate == null ? providers.checker : delegate.getRevocationChecker();
        }
    }
}
