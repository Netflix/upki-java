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

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Establishes why a trust-manager decorator cannot trust peer-supplied issuer
 * ordering.
 */
class IssuerAcquisitionTest {
    private static CertificateFixture issuer;
    private static CertificateFixture decoy;
    private static CertificateFixture unrelated;
    private static CertificateFixture leaf;
    private static KeyStore roots;
    private static X509TrustManager delegate;

    @BeforeAll
    static void certificates() throws Exception {
        issuer = new CertificateFixture(new byte[] {1}, false, true, null);
        decoy = new CertificateFixture(new byte[] {2}, true, true, null);
        unrelated = new CertificateFixture(new byte[] {4}, true, true, null, null,
                "CN=unrelated");
        leaf = new CertificateFixture(new byte[] {3}, true, true, null, issuer.keys);
        roots = KeyStore.getInstance("JKS");
        roots.load(null, null);
        roots.setCertificateEntry("issuer", issuer.certificate);
        TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
        factory.init(roots);
        delegate = (X509TrustManager) factory.getTrustManagers()[0];
    }

    @Test
    void normalVerificationCanAcceptAnIncorrectSecondPeerCertificate() throws Exception {
        X509Certificate[] peer = {leaf.certificate, decoy.certificate, unrelated.certificate, issuer.certificate};
        assertEquals(leaf.certificate.getIssuerX500Principal(), decoy.certificate.getSubjectX500Principal());
        assertThrows(GeneralSecurityException.class, () -> leaf.certificate.verify(decoy.keys.getPublic()));
        delegate.checkServerTrusted(peer, "RSA");
        assertSame(decoy.certificate, peer[1]);
    }

    @Test
    void normalVerificationCanAcceptAnOmittedIssuerFromTheTrustStore() throws Exception {
        delegate.checkServerTrusted(new X509Certificate[] {leaf.certificate}, "RSA");
    }

    @Test
    void publicPkixBuildingReturnsTheAuthenticatedIssuerWhenTrustInputsAreKnown() throws Exception {
        X509CertSelector target = new X509CertSelector();
        target.setCertificate(leaf.certificate);
        PKIXBuilderParameters parameters = new PKIXBuilderParameters(roots, target);
        parameters.setRevocationEnabled(false);
        parameters.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(Arrays.asList(leaf.certificate, decoy.certificate, unrelated.certificate, issuer.certificate))));
        PKIXCertPathBuilderResult built = (PKIXCertPathBuilderResult) CertPathBuilder.getInstance("PKIX").build(parameters);
        assertEquals(1,
                built.getCertPath()
                     .getCertificates()
                     .size());
        assertEquals(issuer.certificate, built.getTrustAnchor().getTrustedCert());
    }
}
