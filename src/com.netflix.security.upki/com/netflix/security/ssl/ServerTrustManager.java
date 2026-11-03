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

package com.netflix.security.ssl;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import com.netflix.security.upki.checker.AuthenticatedPaths;
import com.netflix.security.upki.checker.AuthenticatedPaths.Verification;
import com.netflix.security.upki.checker.ServerCertificateCheck;
import com.netflix.security.upki.provider.InvocationGuard;

/** Internal server-check wrapper preserving the delegate's JSSE capabilities. */
final class ServerTrustManager {
    private ServerTrustManager() {}

    static TrustManager wrap(TrustManager manager, ServerCertificateCheck check) {
        Objects.requireNonNull(check, "check");
        if (manager instanceof Basic && ((Basic) manager).check == check) {
            return manager;
        }
        if (manager instanceof Extended && ((Extended) manager).check == check) {
            return manager;
        }
        if (manager instanceof X509ExtendedTrustManager) {
            return new Extended((X509ExtendedTrustManager) manager, check);
        }
        if (manager instanceof X509TrustManager) {
            return new Basic((X509TrustManager) manager, check);
        }
        return manager;
    }

    private static void server(X509Certificate[] chain, ServerCertificateCheck check, Verification verification) throws CertificateException {
        InvocationGuard guard = InvocationGuard.enter();
        try {
            AuthenticatedPaths.verify(chain, check, verification);
        } finally {
            guard.close();
        }
    }

    private static void client(Verification verification) throws CertificateException {
        InvocationGuard guard = InvocationGuard.enter();
        try {
            verification.verify();
        } finally {
            guard.close();
        }
    }

    private static X509Certificate[] issuers(X509TrustManager manager) {
        InvocationGuard guard = InvocationGuard.enter();
        try {
            return manager.getAcceptedIssuers();
        } finally {
            guard.close();
        }
    }

    private static final class Basic implements X509TrustManager {
        final X509TrustManager delegate;
        final ServerCertificateCheck check;

        Basic(X509TrustManager delegate, ServerCertificateCheck check) {
            this.delegate = delegate;
            this.check = check;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
            server(chain, check, () -> delegate.checkServerTrusted(chain, auth));
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String auth) throws CertificateException {
            client(() -> delegate.checkClientTrusted(chain, auth));
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return issuers(delegate);
        }
    }

    private static final class Extended extends X509ExtendedTrustManager {
        final X509ExtendedTrustManager delegate;
        final ServerCertificateCheck check;

        Extended(X509ExtendedTrustManager delegate, ServerCertificateCheck check) {
            this.delegate = delegate;
            this.check = check;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
            server(chain, check, () -> delegate.checkServerTrusted(chain, auth));
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String auth, Socket socket) throws CertificateException {
            server(chain, check, () -> delegate.checkServerTrusted(chain, auth, socket));
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String auth, SSLEngine engine) throws CertificateException {
            server(chain, check, () -> delegate.checkServerTrusted(chain, auth, engine));
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String auth) throws CertificateException {
            client(() -> delegate.checkClientTrusted(chain, auth));
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String auth, Socket socket) throws CertificateException {
            client(() -> delegate.checkClientTrusted(chain, auth, socket));
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String auth, SSLEngine engine) throws CertificateException {
            client(() -> delegate.checkClientTrusted(chain, auth, engine));
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return issuers(delegate);
        }
    }
}
