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
import java.nio.file.Files;
import java.nio.file.Path;
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
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import com.netflix.security.provider.UpkiProvider;
import com.netflix.security.upki.RevocationDiagnostics.CacheState;
import com.netflix.security.upki.RevocationDiagnostics.Severity;
import com.netflix.security.upki.RevocationResult.Finding;
import com.netflix.security.upki.UpkiConfiguration;
import com.netflix.security.upki.UpkiConfiguration.CacheFailure;
import com.netflix.security.upki.UpkiConfiguration.Handling;

/**
 * Actual public provider, unchanged HTTPS clients, and explicit fixture policy
 * in a fresh JVM.
 */
public final class UpkiProviderProbe {
    private static final List<String> trace = new ArrayList<String>();
    private static Provider trustBase;
    private static Provider validatorBase;
    private static Provider builderBase;
    private static boolean rejectWrapper;
    private static NoSuchAlgorithmException constructionFailure;

    public static void main(String[] args) throws Exception {
        require(args.length == 1, "choose one isolated scenario");
        require(Security.getProvider(UpkiProvider.NAME) == null, "probe requires no pre-installed UPKI provider");
        switch (args[0]) {
            case "install":
                installation();
                break;
            case "https":
                https("open");
                break;
            case "https-closed":
                https("closed");
                break;
            case "https-missing-ignore":
                https("missing-ignore");
                break;
            case "https-missing-fail":
                https("missing-fail");
                break;
            case "https-disabled":
                https("disabled");
                break;
            case "delegation":
                delegation();
                break;
            case "late":
                late();
                break;
            case "layering":
                layering();
                break;
            default:
                throw new AssertionError(args[0]);
        }
        System.out.println("PASS provider " + args[0] + " java=" + System.getProperty("java.version"));
    }

    private static void installation() throws Exception {
        Path directory = Files.createTempDirectory("upki-install-");
        Provider[] original = Security.getProviders();
        String algorithm = Security.getProperty("ssl.TrustManagerFactory.algorithm");
        try {
            UpkiConfiguration configuration = configuration(directory, true, Handling.WARN, CacheFailure.FAIL_OPEN);
            UpkiProvider provider = UpkiProvider.install(configuration);
            require(Security.getProviders()[0] == provider, "not installed first");
            require(
                    Arrays.equals(original,
                            Arrays.copyOfRange(Security.getProviders(), 1, original.length + 1)),
                    "existing provider order changed");
            require(TrustManagerFactory.getInstance("PKIX").getProvider() == provider, "PKIX factory not selected");
            require(TrustManagerFactory.getInstance("UPKI").getProvider() == provider, "explicit factory not selected");
            require(CertPathValidator.getInstance("PKIX").getProvider() == provider, "validator not selected");
            require(CertPathBuilder.getInstance("PKIX").getProvider() == provider, "builder not selected");
            require(algorithm.equals(Security.getProperty("ssl.TrustManagerFactory.algorithm")), "default algorithm changed");
            require(provider.diagnostics().assessments() == 0, "installation performed a check");
            require(UpkiProvider.install(configuration(directory, true, Handling.WARN, CacheFailure.FAIL_OPEN)) == provider, "equivalent installation replaced the provider");
            Provider[] before = Security.getProviders();
            expectInstallFailure(configuration(directory, false, Handling.WARN, CacheFailure.FAIL_OPEN));
            require(Arrays.equals(before, Security.getProviders()), "conflicting install changed registration");
            ExecutorService pool = Executors.newFixedThreadPool(8);
            try {
                List<Callable<UpkiProvider>> tasks = new ArrayList<Callable<UpkiProvider>>();
                for (int i = 0; i < 32; i++) {
                    tasks.add(() -> UpkiProvider.install(configuration(directory, true, Handling.WARN, CacheFailure.FAIL_OPEN)));
                }
                for (Future<UpkiProvider> result : pool.invokeAll(tasks)) {
                    require(result.get() == provider, "concurrent duplicate");
                }
            } finally {
                pool.shutdownNow();
            }
            Security.removeProvider(UpkiProvider.NAME);
            UpkiProvider low = new UpkiProvider(configuration);
            Security.addProvider(low);
            before = Security.getProviders();
            expectInstallFailure(configuration);
            require(Arrays.equals(before, Security.getProviders()), "lower provider was reordered");
            Security.removeProvider(UpkiProvider.NAME);
            Provider foreign = new NamedProvider(UpkiProvider.NAME);
            Security.addProvider(foreign);
            before = Security.getProviders();
            expectInstallFailure(configuration);
            require(Arrays.equals(before, Security.getProviders()), "foreign provider was replaced");
            Security.removeProvider(UpkiProvider.NAME);
            provider = new UpkiProvider(configuration);
            Security.insertProviderAt(provider, 1);
            require(UpkiProvider.install(configuration) == provider, "manual first-priority registration not reused");
            provider.put("MessageDigest.UPKI-Test", "java.lang.Object");
            expectInstallFailure(configuration);
            provider.remove("MessageDigest.UPKI-Test");
            List<Service> services = new ArrayList<Service>(provider.getServices());
            provider.clear();
            before = Security.getProviders();
            expectInstallFailure(configuration);
            require(Arrays.equals(before, Security.getProviders()), "mutated provider was silently repaired");
            for (Service service : services) {
                provider.put(service.getType() + "." + service.getAlgorithm(), service.getClassName());
            }
            require(provider.getServices().size() == 4, "look-alike service fixture");
            expectInstallFailure(configuration);
            require(Arrays.equals(before, Security.getProviders()), "look-alike services were silently repaired");
        } finally {
            Security.removeProvider(UpkiProvider.NAME);
            Files.delete(directory);
        }
        require(Arrays.equals(original, Security.getProviders()), "installation cleanup changed original order");
    }

    private static void expectInstallFailure(UpkiConfiguration configuration) {
        try {
            UpkiProvider.install(configuration);
            throw new AssertionError("conflicting installation accepted");
        } catch (ProviderException expected) {
            require(expected.getMessage().contains(UpkiProvider.NAME), "uninformative installation rejection");
        }
    }

    private static void https(String mode) throws Exception {
        require("PKIX".equalsIgnoreCase(TrustManagerFactory.getDefaultAlgorithm()), "default HTTPS probe requires PKIX");
        try (ProviderTlsFixture fixture = new ProviderTlsFixture()) {
            boolean disabled = mode.equals("disabled");
            Handling missing = mode.equals("missing-ignore")
                    ? Handling.IGNORE
                    : mode.equals("missing-fail") ? Handling.FAIL : Handling.WARN;
            CacheFailure failure = mode.equals("closed") ? CacheFailure.FAIL_CLOSED : CacheFailure.FAIL_OPEN;
            if (!mode.startsWith("missing")) {
                fixture.cache(disabled);
            }
            if (mode.equals("closed")) {
                Files.write(fixture.cache.resolve("index.bin"), new byte[0]);
            }
            UpkiProvider provider = UpkiProvider.install(configuration(fixture.cache, !disabled, missing, failure));
            if (mode.startsWith("missing")) {
                SSLHandshakeException rejection = fixture.request(false, missing == Handling.FAIL);
                if (rejection != null) {
                    require(message(rejection, "UPKI"), "missing-index rejection changed");
                }
                require(provider.diagnostics().count(Finding.NO_DATA) == 1, "absence not diagnosed");
                require(provider.diagnostics().cacheSeverity() == (missing == Handling.FAIL ? Severity.ERROR : Severity.NONE), "missing-index severity");
                return;
            }
            if (mode.equals("closed")) {
                require(message(fixture.request(false, true), "UPKI"), "strict cache rejection changed");
                require(provider.diagnostics().count(Finding.FAILED) == 1, "failure not diagnosed");
                require(provider.diagnostics().cacheFailOpen() == 0, "closed cache was open");
                return;
            }
            if (disabled) {
                fixture.request(false, false);
                CertificateFixture malformed = new CertificateFixture(new byte[] {122}, true, true,
                        new byte[] {0, 0}, fixture.issuer.keys, "CN=localhost");
                fixture.request(malformed, fixture.issuer, false, false, null);
                require(provider.diagnostics().count(Finding.DISABLED) == 2, "disabled input decoding");
                require(provider.diagnostics().cacheState() == CacheState.DISABLED, "disabled cache access");
                fixture.request(true, true);
                require(provider.diagnostics().assessments() == 2, "disabled policy bypassed hostname rejection");
                return;
            }
            fixture.request(false, false);
            require(provider.diagnostics().count(Finding.NOT_REVOKED) == 1, "default HTTPS did not check revocation");
            fixture.cache(true);
            require(message(fixture.request(false, true), "UPKI"), "revocation rejection changed");
            require(provider.diagnostics().count(Finding.REVOKED) == 1, "revocation not diagnosed");
            Files.write(fixture.cache.resolve("index.bin"), new byte[0]);
            fixture.request(false, false);
            require(provider.diagnostics().cacheFailOpen() == 1, "fail-open not diagnosed");
            require(provider.diagnostics().cacheState() == CacheState.FAILED, "failure hidden");
            long checked = provider.diagnostics().assessments();
            require(!message(fixture.request(true, true), "UPKI"), "hostname rejection replaced");
            require(provider.diagnostics().assessments() == checked, "hostname rejection reached enforcement");
            CertificateFixture untrustedIssuer = new CertificateFixture(new byte[] {123}, false, true, null);
            CertificateFixture untrustedLeaf = new CertificateFixture(new byte[] {124}, true, true, null, untrustedIssuer.keys,
                    "CN=localhost");
            require(!message(fixture.request(untrustedLeaf, untrustedIssuer, false, true, null), "UPKI"), "normal validation failure replaced");
            require(provider.diagnostics().assessments() == checked, "normal rejection reached enforcement");
            Files.delete(fixture.cache.resolve("index.bin"));
            fixture.request(false, false);
            require(provider.diagnostics().count(Finding.NO_DATA) == 1, "warn absence not diagnosed");
            require(provider.diagnostics().cacheSeverity() == Severity.WARNING, "warn absence severity");
            fixture.cache(false);
            fixture.request(false, false);
            require(provider.diagnostics()
                            .lastRecoveryTime()
                            .isPresent(),
                    "recovery not diagnosed");
            require(provider.diagnostics().degradationEpisode() == 1, "one outage split into multiple episodes");
            long total = provider.diagnostics().assessments();
            require(UpkiProvider.install(configuration(fixture.cache, true, Handling.WARN, CacheFailure.FAIL_OPEN)) == provider, "equivalent install replaced live provider");
            require(provider.diagnostics().assessments() == total, "installation reset diagnostics");
            TrustManagerFactory explicit = TrustManagerFactory.getInstance("UPKI");
            explicit.init(fixture.roots);
            ((X509TrustManager) explicit.getTrustManagers()[0]).checkServerTrusted(new X509Certificate[] {fixture.leaf.certificate, fixture.issuer.certificate}, "RSA");
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(fixture.leaf.certificate);
            PKIXBuilderParameters parameters = new PKIXBuilderParameters(fixture.roots, target);
            parameters.setRevocationEnabled(false);
            explicit.init(new CertPathTrustManagerParameters(parameters));
            ((X509TrustManager) explicit.getTrustManagers()[0]).checkServerTrusted(new X509Certificate[] {fixture.leaf.certificate, fixture.issuer.certificate}, "RSA");
            require(provider.diagnostics().assessments() == total + 2, "initialization forms did not share diagnostics");
            require(CertPathValidator.getInstance("PKIX").getRevocationChecker() instanceof PKIXRevocationChecker, "validator checker");
            require(CertPathBuilder.getInstance("PKIX").getRevocationChecker() instanceof PKIXRevocationChecker, "builder checker");
            require(provider.diagnostics().assessments() == total + 2, "non-TLS observation performed revocation checks");
        } finally {
            Security.removeProvider(UpkiProvider.NAME);
        }
    }

    private static void late() throws Exception {
        try (ProviderTlsFixture fixture = new ProviderTlsFixture()) {
            SSLSocketFactory old = HttpsURLConnection.getDefaultSSLSocketFactory();
            fixture.cache(true);
            UpkiProvider provider = UpkiProvider.install(configuration(fixture.cache, true, Handling.WARN, CacheFailure.FAIL_OPEN));
            require(HttpsURLConnection.getDefaultSSLSocketFactory() == old, "installation replaced cached defaults");
            fixture.request(false, false);
            require(provider.diagnostics().assessments() == 0, "late installation rewrote an existing trust manager");
            SSLContext fresh = SSLContext.getInstance("TLS");
            fresh.init(null, null, null);
            require(message(fixture.request(fixture.leaf, fixture.issuer, false, true, fresh.getSocketFactory()), "UPKI"), "fresh context did not select installed provider");
            require(provider.diagnostics().count(Finding.REVOKED) == 1, "fresh context not diagnosed");
        } finally {
            Security.removeProvider(UpkiProvider.NAME);
        }
    }

    private static void layering() throws Exception {
        try (ProviderTlsFixture fixture = new ProviderTlsFixture()) {
            fixture.cache(true);
            UpkiProvider global = UpkiProvider.install(configuration(fixture.cache, true, Handling.WARN, CacheFailure.FAIL_OPEN));
            UpkiProvider local = new UpkiProvider(configuration(fixture.cache, false, Handling.IGNORE, CacheFailure.FAIL_OPEN));
            TrustManagerFactory factory = TrustManagerFactory.getInstance("UPKI", local);
            factory.init(fixture.roots);
            X509TrustManager manager = (X509TrustManager) factory.getTrustManagers()[0];
            try {
                manager.checkServerTrusted(new X509Certificate[] {fixture.leaf.certificate}, "RSA");
                throw new AssertionError("local disabled configuration bypassed global revocation");
            } catch (CertificateException expected) {
                require(message(expected, "UPKI"), "wrong layered rejection");
            }
            require(global.diagnostics().count(Finding.REVOKED) == 1, "global enforcement bypassed");
            require(local.diagnostics().assessments() == 0, "rejected delegation reached local enforcement");
            fixture.cache(false);
            manager.checkServerTrusted(new X509Certificate[] {fixture.leaf.certificate}, "RSA");
            require(local.diagnostics().count(Finding.DISABLED) == 1, "independent local diagnostic lifetime");
            UpkiProvider other = new UpkiProvider(configuration(fixture.cache, true, Handling.WARN, CacheFailure.FAIL_OPEN));
            TrustManagerFactory separate = TrustManagerFactory.getInstance("PKIX", other);
            separate.init(fixture.roots);
            try {
                ((X509TrustManager) separate.getTrustManagers()[0]).checkServerTrusted(new X509Certificate[] {fixture.leaf.certificate}, "RSA");
                throw new AssertionError("separate enforcement identities unexpectedly shared observations");
            } catch (CertificateException expected) {
                require(other.diagnostics().count(Finding.ISSUER_UNAVAILABLE) == 1, "layered observation limit hidden");
            }
        } finally {
            Security.removeProvider(UpkiProvider.NAME);
        }
    }

    private static void delegation() throws Exception {
        trustBase = TrustManagerFactory.getInstance("PKIX").getProvider();
        validatorBase = CertPathValidator.getInstance("PKIX").getProvider();
        builderBase = CertPathBuilder.getInstance("PKIX").getProvider();
        Wrapper base = new Wrapper("base");
        Wrapper a = new Wrapper("A");
        Wrapper b = new Wrapper("B");
        Security.insertProviderAt(base, 1);
        Security.insertProviderAt(b, 1);
        Security.insertProviderAt(a, 1);
        try (ProviderTlsFixture fixture = new ProviderTlsFixture()) {
            fixture.cache(false);
            UpkiProvider provider = UpkiProvider.install(configuration(fixture.cache, true, Handling.WARN, CacheFailure.FAIL_OPEN));
            fixture.request(false, false);
            require(trace.contains("A.server") && trace.contains("B.server"), "opaque trust wrappers bypassed: " + trace);
            require(trace.contains("A.validate") && trace.contains("B.validate"), "PKIX wrappers bypassed: " + trace);
            require(provider.diagnostics().assessments() == 1, "nested adapters enforced more than once");
            rejectWrapper = true;
            Files.write(fixture.cache.resolve("index.bin"), new byte[0]);
            require(message(fixture.request(false, true), "opaque A rejected"), "opaque wrapper rejection replaced");
            require(provider.diagnostics().assessments() == 1, "opaque rejection reached cache fail-open");
            rejectWrapper = false;
            fixture.request(false, false);
            require(provider.diagnostics().cacheFailOpen() == 1, "wrapped cache policy not reached");
            constructionFailure = new NoSuchAlgorithmException("opaque construction failure");
            for (String type : new String[] {"TrustManagerFactory", "CertPathValidator", "CertPathBuilder"}) {
                try {
                    instance(type, null);
                    throw new AssertionError("construction failure skipped " + type);
                } catch (ProviderException expected) {
                    require(expected.getCause() == constructionFailure, "construction failure cause lost");
                }
            }
            constructionFailure = null;
            TrustManagerFactory.getInstance("PKIX");
            CertPathValidator.getInstance("PKIX");
            CertPathBuilder.getInstance("PKIX");
        } finally {
            for (String name : new String[] {UpkiProvider.NAME, a.getName(), b.getName(),
                    base.getName()}) {
                Security.removeProvider(name);
            }
        }
    }

    private static UpkiConfiguration configuration(Path directory, boolean enabled, Handling missing,
            CacheFailure failure) {
        return UpkiConfiguration.builder()
                .cacheDirectory(directory)
                .enabled(enabled)
                .missingIndex(missing)
                .cacheFailure(failure)
                .missingScts(Handling.IGNORE)
                .coverage(Handling.IGNORE)
                .unsupportedVerification(Handling.FAIL)
                .build();
    }

    private static boolean message(Throwable failure, String fragment) {
        for (int depth = 0;
             failure != null && depth < 64;
             depth++, failure = failure.getCause()) {
            if (failure.getMessage() != null && failure.getMessage().contains(fragment)) {
                return true;
            }
        }
        return false;
    }

    static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static class NamedProvider extends Provider {
        private static final long serialVersionUID = 1L;

        @SuppressWarnings("deprecation")
        NamedProvider(String name) {
            super(name, 1.0, "Provider installation test");
        }
    }

    private static final class Wrapper extends NamedProvider {
        private static final long serialVersionUID = 1L;
        final String label;

        Wrapper(String label) {
            super("UPKI-ProviderProbe-" + label);
            this.label = label;
            for (String type : new String[] {"TrustManagerFactory", "CertPathValidator", "CertPathBuilder"}) {
                putService(new Service(this, type, "PKIX", Wrapper.class.getName(), null,
                        null) {
                    public Object newInstance(Object unused) throws NoSuchAlgorithmException {
                        if (label.equals("A") && constructionFailure != null) {
                            throw constructionFailure;
                        }
                        Object delegate = delegate(Wrapper.this, getType());
                        if (delegate instanceof TrustManagerFactory) {
                            return new Trust((TrustManagerFactory) delegate, label);
                        }
                        if (delegate instanceof CertPathValidator) {
                            return new Validator((CertPathValidator) delegate, label);
                        }
                        return new Builder((CertPathBuilder) delegate);
                    }
                });
            }
        }
    }

    private static Object instance(String type, Provider provider) throws NoSuchAlgorithmException {
        switch (type) {
            case "TrustManagerFactory":
                return provider == null ? TrustManagerFactory.getInstance("PKIX") : TrustManagerFactory.getInstance("PKIX", provider);
            case "CertPathValidator":
                return provider == null ? CertPathValidator.getInstance("PKIX") : CertPathValidator.getInstance("PKIX", provider);
            case "CertPathBuilder":
                return provider == null ? CertPathBuilder.getInstance("PKIX") : CertPathBuilder.getInstance("PKIX", provider);
            default:
                throw new AssertionError(type);
        }
    }

    private static Object delegate(Wrapper owner, String type) throws NoSuchAlgorithmException {
        trace.add(owner.label + "." + type);
        if (owner.label.equals("base")) {
            return instance(type,
                    type.equals("TrustManagerFactory")
                            ? trustBase
                            : type.equals("CertPathValidator") ? validatorBase : builderBase);
        }
        for (Provider provider : Security.getProviders()) {
            if (provider != owner && provider.getService(type, "PKIX") != null) {
                return instance(type, provider);
            }
        }
        throw new NoSuchAlgorithmException(type);
    }

    private static final class Trust extends TrustManagerFactorySpi {
        private final TrustManagerFactory delegate;
        private final String label;

        Trust(TrustManagerFactory delegate, String label) {
            this.delegate = delegate;
            this.label = label;
        }

        protected void engineInit(KeyStore store) throws KeyStoreException {
            delegate.init(store);
        }

        protected void engineInit(ManagerFactoryParameters parameters) throws InvalidAlgorithmParameterException {
            delegate.init(parameters);
        }

        protected TrustManager[] engineGetTrustManagers() {
            TrustManager[] managers = delegate.getTrustManagers().clone();
            for (int i = 0; i < managers.length; i++) {
                if (managers[i] instanceof X509ExtendedTrustManager) {
                    managers[i] = new Manager((X509ExtendedTrustManager) managers[i], label);
                }
            }
            return managers;
        }
    }

    private static final class Manager extends X509ExtendedTrustManager {
        private final X509ExtendedTrustManager delegate;
        private final String label;

        Manager(X509ExtendedTrustManager delegate, String label) {
            this.delegate = delegate;
            this.label = label;
        }

        private void server(Verification verification) throws CertificateException {
            trace.add(label + ".server");
            verification.verify();
            if (label.equals("A") && rejectWrapper) {
                throw new CertificateException("opaque A rejected");
            }
        }

        public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
            server(() -> delegate.checkServerTrusted(chain, auth));
        }

        public void checkServerTrusted(X509Certificate[] chain, String auth, Socket socket) throws CertificateException {
            server(() -> delegate.checkServerTrusted(chain, auth, socket));
        }

        public void checkServerTrusted(X509Certificate[] chain, String auth, SSLEngine engine) throws CertificateException {
            server(() -> delegate.checkServerTrusted(chain, auth, engine));
        }

        public void checkClientTrusted(X509Certificate[] chain, String auth) throws CertificateException {
            delegate.checkClientTrusted(chain, auth);
        }

        public void checkClientTrusted(X509Certificate[] chain, String auth, Socket socket) throws CertificateException {
            delegate.checkClientTrusted(chain, auth, socket);
        }

        public void checkClientTrusted(X509Certificate[] chain, String auth, SSLEngine engine) throws CertificateException {
            delegate.checkClientTrusted(chain, auth, engine);
        }

        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }
    }

    private interface Verification {
        void verify() throws CertificateException;
    }

    private static final class Validator extends CertPathValidatorSpi {
        private final CertPathValidator delegate;
        private final String label;

        Validator(CertPathValidator delegate, String label) {
            this.delegate = delegate;
            this.label = label;
        }

        public CertPathValidatorResult engineValidate(CertPath path, CertPathParameters parameters) throws CertPathValidatorException, InvalidAlgorithmParameterException {
            trace.add(label + ".validate");
            return delegate.validate(path, parameters);
        }

        public CertPathChecker engineGetRevocationChecker() {
            return delegate.getRevocationChecker();
        }
    }

    private static final class Builder extends CertPathBuilderSpi {
        private final CertPathBuilder delegate;

        Builder(CertPathBuilder delegate) {
            this.delegate = delegate;
        }

        public CertPathBuilderResult engineBuild(CertPathParameters parameters) throws CertPathBuilderException, InvalidAlgorithmParameterException {
            return delegate.build(parameters);
        }

        public CertPathChecker engineGetRevocationChecker() {
            return delegate.getRevocationChecker();
        }
    }
}
