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
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
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
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
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
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509TrustManager;

import com.netflix.security.upki.checker.CacheChecker;
import com.netflix.security.upki.checker.CertificateInputs;
import com.netflix.security.upki.checker.CheckDiagnostics.CacheState;
import com.netflix.security.upki.checker.CheckPolicy;
import com.netflix.security.upki.checker.CheckPolicy.CacheFailure;
import com.netflix.security.upki.checker.CheckPolicy.Handling;
import com.netflix.security.upki.checker.RevocationEnforcer;
import com.netflix.security.upki.checker.RevocationEnforcer.Finding;
import com.netflix.security.upki.checker.RevocationEnforcer.Severity;
import com.netflix.security.upki.checker.ServerCertificateCheck;
import com.netflix.security.upki.provider.DelegatingService;

/**
 * Isolated PKIX integration with explicit fixture policy, not production defaults.
 */
public final class DelegatingTlsProbe {
    private static final String ALGORITHM = "PKIX";
    private static boolean delayed;
    private static NoSuchAlgorithmException constructionFailure;
    private static final List<String> trace = new ArrayList<>();
    private static Provider trustBase;
    private static Provider validatorBase;
    private static Provider builderBase;
    private static Wrapper owner;
    private static X509Certificate authenticatedIssuer;
    private static boolean basicView;
    private static boolean rejectCheck;
    private static RevocationEnforcer enforcer;
    private static Finding expectedFinding;
    private static boolean expectPolicyRejection;
    private static final AtomicInteger checks = new AtomicInteger();
    private static final ServerCertificateCheck CHECK = (leaf, evidence) -> {
        checks.incrementAndGet();
        require(!evidence.truncated() && evidence.paths().size() == 1, "missing or duplicate authenticated path");
        X509Certificate issuer = evidence.paths()
                .get(0)
                .issuer();
        require(authenticatedIssuer.equals(issuer), "wrong authenticated issuer");
        if (rejectCheck) {
            throw new CertificateException("UPKI test check rejected");
        }
        if (enforcer != null) {
            try {
                enforcer.check(leaf, evidence);
            } finally {
                require(enforcer.snapshot()
                                .lastFinding()
                                .get()
                        == expectedFinding,
                        "unexpected finding: " + enforcer.snapshot().lastFinding());
            }
        }
    };

    public static void main(String[] args) throws Exception {
        trustBase = TrustManagerFactory.getInstance("PKIX").getProvider();
        validatorBase = CertPathValidator.getInstance("PKIX").getProvider();
        builderBase = CertPathBuilder.getInstance("PKIX").getProvider();
        owner = new Wrapper("owner");
        Wrapper a = new Wrapper("A");
        Wrapper b = new Wrapper("B");
        Wrapper base = new Wrapper("base");
        require(Security.insertProviderAt(base, 1) == 1, "base registration");
        require(Security.insertProviderAt(b, 1) == 1, "wrapper B registration");
        require(Security.insertProviderAt(a, 1) == 1, "wrapper A registration");
        require(Security.insertProviderAt(owner, 1) == 1, "adapter registration");
        try {
            CertificateFixture issuer = new CertificateFixture(new byte[] {1}, false, true, null);
            byte[] scts = CertificateFixture.list(CertificateFixture.sct(1, 150, new byte[0], new byte[] {1}));
            CertificateFixture leaf = new CertificateFixture(new byte[] {2}, true, true, scts, issuer.keys,
                    "CN=localhost");
            authenticatedIssuer = issuer.certificate;
            KeyStore roots = KeyStore.getInstance("JKS");
            roots.load(null, null);
            roots.setCertificateEntry("issuer", issuer.certificate);
            TrustManagerFactory trust = TrustManagerFactory.getInstance(ALGORITHM);
            require(trace.equals(Arrays.asList("A", "B", "base")), "trust construction: " + trace);
            trust.init(roots);
            ((X509TrustManager) trust.getTrustManagers()[0]).checkServerTrusted(new X509Certificate[] {leaf.certificate, issuer.certificate}, "RSA");
            int before = checks.get();
            tls(trust, leaf, issuer, false);
            require(checks.get() == before + 1, "server enforcement did not run exactly once");
            before = checks.get();
            tls(trust, leaf, issuer, true);
            require(checks.get() == before, "hostname rejection reached enforcement");
            rejectCheck = true;
            tls(trust, leaf, issuer, false);
            rejectCheck = false;
            basicView = true;
            before = checks.get();
            tls(trust, leaf, issuer, false);
            tls(trust, leaf, issuer, true);
            require(checks.get() == before + 2, "basic-manager ordering changed");
            basicView = false;
            trace.clear();
            CertPathValidator validator = CertPathValidator.getInstance(ALGORITHM);
            require(trace.equals(Arrays.asList("A", "B", "base")), "validator construction: " + trace);
            CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(Collections.singletonList(leaf.certificate));
            PKIXParameters parameters = new PKIXParameters(roots);
            parameters.setRevocationEnabled(false);
            PKIXCertPathValidatorResult validated = (PKIXCertPathValidatorResult) validator.validate(path, parameters);
            require(issuer.certificate.equals(validated.getTrustAnchor()
                    .getTrustedCert()),
                    "wrong validator anchor");
            require(validator.getRevocationChecker() instanceof PKIXRevocationChecker, "validator checker");
            trace.clear();
            CertPathBuilder builder = CertPathBuilder.getInstance(ALGORITHM);
            require(trace.equals(Arrays.asList("A", "B", "base")), "builder construction: " + trace);
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(leaf.certificate);
            PKIXBuilderParameters buildParameters = new PKIXBuilderParameters(roots, target);
            buildParameters.setRevocationEnabled(false);
            buildParameters.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(Arrays.asList(leaf.certificate, issuer.certificate))));
            PKIXCertPathBuilderResult built = (PKIXCertPathBuilderResult) builder.build(buildParameters);
            require(issuer.certificate.equals(built.getTrustAnchor()
                    .getTrustedCert()),
                    "wrong builder anchor");
            require(builder.getRevocationChecker() instanceof PKIXRevocationChecker, "builder checker");
            trust.init(new CertPathTrustManagerParameters(buildParameters));
            ((X509TrustManager) trust.getTrustManagers()[0]).checkServerTrusted(new X509Certificate[] {leaf.certificate}, "RSA");
            constructionFailure = new NoSuchAlgorithmException("do not skip this wrapper");
            for (String type : Arrays.asList("TrustManagerFactory", "CertPathValidator", "CertPathBuilder")) {
                try {
                    unpinnedInstance(type);
                    throw new AssertionError("construction failure skipped " + type);
                } catch (ProviderException expected) {
                    require(expected.getCause() == constructionFailure, "construction failure cause lost");
                }
            }
            constructionFailure = null;
            delayed = true;
            try {
                CertPathValidator.getInstance("PKIX").validate(path, parameters);
                throw new AssertionError("delayed selection cycle accepted");
            } catch (ProviderException expected) {
                require(expected.getMessage().contains("delegation"), "unexpected provider error");
            }
            delayed = false;
            CertPathValidator.getInstance("PKIX").validate(path, parameters);
            Path cache = Files.createTempDirectory("upki-tls-cache-");
            try {
                CacheChecker checker = new CacheChecker(Collections.singletonList(cache));
                enforcer = new RevocationEnforcer(checker, policy(true, Handling.WARN, CacheFailure.FAIL_OPEN));
                byte[] issuerHash = CertificateInputs.read(leaf.certificate, issuer.certificate).issuerSpkiHash();
                expectedFinding = Finding.NOT_REVOKED;
                CacheFixture.write(cache, issuerHash, false);
                tls(trust, leaf, issuer, false);
                expectedFinding = Finding.REVOKED;
                expectPolicyRejection = true;
                CacheFixture.write(cache, issuerHash, true);
                tls(trust, leaf, issuer, false);
                expectedFinding = Finding.FAILED;
                expectPolicyRejection = false;
                Files.write(cache.resolve("index.bin"), new byte[0]);
                tls(trust, leaf, issuer, false);
                require(enforcer.snapshot().cacheFailOpen() == 1, "fail-open was not counted");
                require(enforcer.snapshot().cacheState() == CacheState.FAILED, "cache failure was hidden");
                basicView = true;
                tls(trust, leaf, issuer, true);
                basicView = false;
                require(enforcer.snapshot().cacheFailOpen() == 2, "basic manager did not reach fail-open policy");
                CacheFixture.write(cache, issuerHash, false);
                expectedFinding = Finding.NOT_REVOKED;
                tls(trust, leaf, issuer, false);
                require(enforcer.snapshot()
                                .lastRecoveryTime()
                                .isPresent(),
                        "cache recovery was not recorded");
                enforcer = new RevocationEnforcer(checker, policy(true, Handling.FAIL, CacheFailure.FAIL_CLOSED));
                Files.write(cache.resolve("index.bin"), new byte[0]);
                expectedFinding = Finding.FAILED;
                expectPolicyRejection = true;
                tls(trust, leaf, issuer, false);
                Files.delete(cache.resolve("index.bin"));
                for (Handling handling : Handling.values()) {
                    enforcer = new RevocationEnforcer(checker, policy(true, handling, CacheFailure.FAIL_CLOSED));
                    expectedFinding = Finding.NO_DATA;
                    expectPolicyRejection = handling == Handling.FAIL;
                    tls(trust, leaf, issuer, false);
                    require(enforcer.snapshot().cacheState() == CacheState.ABSENT, "missing index not recorded");
                    require(enforcer.snapshot().cacheSeverity()
                            == (handling == Handling.IGNORE
                                    ? Severity.NONE
                                    : handling == Handling.WARN ? Severity.WARNING : Severity.ERROR),
                            "missing index severity");
                }
                Files.write(cache.resolve("index.bin"), new byte[0]);
                enforcer = new RevocationEnforcer(checker, policy(false, Handling.FAIL, CacheFailure.FAIL_CLOSED));
                expectedFinding = Finding.DISABLED;
                expectPolicyRejection = false;
                tls(trust, leaf, issuer, false);
                basicView = true;
                tls(trust, leaf, issuer, true);
                basicView = false;
                require(enforcer.snapshot().cacheFailures() == 0, "disabled checking accessed the cache");
                require(enforcer.snapshot().count(Finding.DISABLED) == 2, "disabled assessments not recorded");
            } finally {
                enforcer = null;
                Files.deleteIfExists(cache.resolve("index.bin"));
                Files.deleteIfExists(cache.resolve("test.filter"));
                Files.delete(cache);
            }
            System.out.println("PASS SPI adapters and TLS java=" + System.getProperty("java.version"));
        } finally {
            for (Provider provider : Arrays.asList(owner, a, b, base)) {
                Security.removeProvider(provider.getName());
            }
        }
    }

    private static CheckPolicy policy(boolean enabled, Handling missingIndex, CacheFailure cacheFailure) {
        return new CheckPolicy(enabled, missingIndex, cacheFailure, Handling.IGNORE, Handling.IGNORE, Handling.FAIL);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static Object unpinnedInstance(String type) throws NoSuchAlgorithmException {
        if (type.equals("TrustManagerFactory")) {
            return TrustManagerFactory.getInstance(ALGORITHM);
        }
        if (type.equals("CertPathValidator")) {
            return CertPathValidator.getInstance(ALGORITHM);
        }
        return CertPathBuilder.getInstance(ALGORITHM);
    }

    private static Object instance(String type, Provider provider) throws NoSuchAlgorithmException {
        if (type.equals("TrustManagerFactory")) {
            return TrustManagerFactory.getInstance(ALGORITHM, provider);
        }
        if (type.equals("CertPathValidator")) {
            return CertPathValidator.getInstance(ALGORITHM, provider);
        }
        return CertPathBuilder.getInstance(ALGORITHM, provider);
    }

    private static Object delegate(Wrapper wrapper, String type) throws NoSuchAlgorithmException {
        trace.add(wrapper.label);
        if (wrapper.label.equals("base")) {
            if (type.equals("TrustManagerFactory")) {
                return TrustManagerFactory.getInstance("PKIX", trustBase);
            }
            if (type.equals("CertPathValidator")) {
                return CertPathValidator.getInstance("PKIX", validatorBase);
            }
            return CertPathBuilder.getInstance("PKIX", builderBase);
        }
        for (Provider provider : Security.getProviders()) {
            if (provider != wrapper && provider.getService(type, ALGORITHM) != null) {
                return instance(type, provider);
            }
        }
        throw new NoSuchAlgorithmException(type);
    }

    private static final class Wrapper extends Provider {
        private static final long serialVersionUID = 1L;
        final String label;

        @SuppressWarnings("deprecation")
        Wrapper(String label) {
            super("UPKI-TLSProbe-" + label, 1.0, "Test-only PKIX adapter integration");
            this.label = label;
            for (String type : Arrays.asList("TrustManagerFactory", "CertPathValidator", "CertPathBuilder")) {
                if (label.equals("owner")) {
                    putService(type.equals("TrustManagerFactory") ? DelegatingService.checkedTrustManagerFactory(this, ALGORITHM, ALGORITHM, Collections.emptyList(), CHECK) : new DelegatingService(this, type, ALGORITHM, ALGORITHM, Collections.emptyList()));
                    continue;
                }
                putService(new Service(this, type, ALGORITHM, Wrapper.class.getName(), null,
                        null) {
                    public Object newInstance(Object unused) throws NoSuchAlgorithmException {
                        if (label.equals("A") && constructionFailure != null) {
                            throw constructionFailure;
                        }
                        if (label.equals("A") && delayed && getType().equals("CertPathValidator")) {
                            return new LateValidator();
                        }
                        Object facade = delegate(Wrapper.this, getType());
                        if (facade instanceof TrustManagerFactory) {
                            return new Trust((TrustManagerFactory) facade);
                        }
                        if (facade instanceof CertPathValidator) {
                            return new Validator((CertPathValidator) facade);
                        }
                        return new Builder((CertPathBuilder) facade);
                    }
                });
            }
        }
    }

    private static final class Trust extends TrustManagerFactorySpi {
        final TrustManagerFactory delegate;

        Trust(TrustManagerFactory delegate) {
            this.delegate = delegate;
        }

        protected void engineInit(KeyStore store) throws KeyStoreException {
            delegate.init(store);
        }

        protected void engineInit(ManagerFactoryParameters parameters) throws InvalidAlgorithmParameterException {
            delegate.init(parameters);
        }

        protected TrustManager[] engineGetTrustManagers() {
            TrustManager[] managers = delegate.getTrustManagers();
            if (basicView && delegate.getProvider() == trustBase) {
                managers = managers.clone();
                for (int i = 0; i < managers.length; i++) {
                    if (managers[i] instanceof X509TrustManager) {
                        managers[i] = new BasicView((X509TrustManager) managers[i]);
                    }
                }
            }
            return managers;
        }
    }

    private static final class BasicView implements X509TrustManager {
        private final X509TrustManager delegate;

        BasicView(X509TrustManager delegate) {
            this.delegate = delegate;
        }

        public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
            delegate.checkServerTrusted(chain, auth);
        }

        public void checkClientTrusted(X509Certificate[] chain, String auth) throws CertificateException {
            delegate.checkClientTrusted(chain, auth);
        }

        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }
    }

    private static final class Validator extends CertPathValidatorSpi {
        final CertPathValidator delegate;

        Validator(CertPathValidator delegate) {
            this.delegate = delegate;
        }

        public CertPathValidatorResult engineValidate(CertPath path, CertPathParameters parameters) throws CertPathValidatorException, InvalidAlgorithmParameterException {
            return delegate.validate(path, parameters);
        }

        public CertPathChecker engineGetRevocationChecker() {
            return delegate.getRevocationChecker();
        }
    }

    private static final class Builder extends CertPathBuilderSpi {
        final CertPathBuilder delegate;

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

    private static final class LateValidator extends CertPathValidatorSpi {
        public CertPathValidatorResult engineValidate(CertPath path, CertPathParameters parameters) throws CertPathValidatorException, InvalidAlgorithmParameterException {
            try {
                return CertPathValidator.getInstance("PKIX").validate(path, parameters);
            } catch (NoSuchAlgorithmException failure) {
                throw new ProviderException(failure);
            }
        }
    }

    private static void tls(TrustManagerFactory trust, CertificateFixture leaf, CertificateFixture issuer,
                            boolean wrongName)
            throws Exception {
        boolean expectedFailure = wrongName || rejectCheck || expectPolicyRejection;
        KeyStore identity = KeyStore.getInstance("JKS");
        identity.load(null, null);
        identity.setKeyEntry("server", leaf.keys.getPrivate(), "changeit".toCharArray(),
                new Certificate[] {leaf.certificate, issuer.certificate});
        KeyManagerFactory keys = KeyManagerFactory.getInstance("SunX509");
        keys.init(identity, "changeit".toCharArray());
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(keys.getKeyManagers(), new TrustManager[0], null);
        SSLContext clientContext = SSLContext.getInstance("TLS");
        clientContext.init(null, trust.getTrustManagers(), null);
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try (SSLServerSocket server = (SSLServerSocket) serverContext.getServerSocketFactory().createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            server.setSoTimeout(10000);
            Future<?> serving = worker.submit(() -> {
                try (SSLSocket socket = (SSLSocket) server.accept()) {
                    socket.setSoTimeout(10000);
                    socket.startHandshake();
                } catch (IOException failure) {
                    if (!expectedFailure) {
                        throw new UncheckedIOException(failure);
                    }
                }
            });
            try (Socket connection = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort());
                 SSLSocket client = (SSLSocket) clientContext.getSocketFactory().createSocket(connection, wrongName ? "wrong.invalid" : "localhost", server.getLocalPort(),
                         true)) {
                client.setSoTimeout(10000);
                SSLParameters parameters = client.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                client.setSSLParameters(parameters);
                try {
                    client.startHandshake();
                    require(!expectedFailure, "expected rejection was lost");
                } catch (SSLHandshakeException failure) {
                    if (!expectedFailure) {
                        throw failure;
                    }
                    require(failure.getMessage().contains(wrongName ? "wrong.invalid" : "UPKI"),
                            "wrong handshake rejection: " + failure);
                }
            }
            serving.get(15, TimeUnit.SECONDS);
        } finally {
            worker.shutdownNow();
        }
    }
}
