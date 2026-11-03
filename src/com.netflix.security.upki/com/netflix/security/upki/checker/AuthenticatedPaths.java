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

import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/** Internal transactional observation of actual delegated PKIX operations. */
public final class AuthenticatedPaths {
    private static final int MAX_PATHS = 32;
    private static final ThreadLocal<Scope> CURRENT = new ThreadLocal<Scope>();
    private static final Operation UNOBSERVED = new Operation(null);

    private AuthenticatedPaths() {}

    public static void verify(X509Certificate[] chain, ServerCertificateCheck check, Verification verification) throws CertificateException {
        Objects.requireNonNull(check, "check");
        Objects.requireNonNull(verification, "verification");
        X509Certificate leaf = chain == null || chain.length == 0
                ? null
                : chain[0];
        Scope previous = CURRENT.get();
        if (previous != null
                && previous.check == check
                && leaf != null
                && leaf.equals(previous.leaf)) {
            previous.forward(verification);
            return;
        }
        Scope scope = new Scope(leaf, check);
        CURRENT.set(scope);
        Result result;
        try {
            verification.verify();
            if (leaf == null) {
                throw new CertificateException("Trust manager accepted a missing server certificate");
            }
            result = new Result(scope.paths, scope.truncated);
        } finally {
            if (previous == null) {
                CURRENT.remove();
            } else {
                CURRENT.set(previous);
            }
        }
        // Do not let policy execution add observations to this completed verification.
        check.check(leaf, result);
    }

    public static Operation begin() {
        Scope scope = CURRENT.get();
        return scope == null ? UNOBSERVED : new Operation(scope);
    }

    @FunctionalInterface
    public interface Verification {
        void verify() throws CertificateException;
    }

    public static final class Result {
        private final List<Path> paths;
        private final boolean truncated;

        private Result(List<Path> paths, boolean truncated) {
            this.paths = Collections.unmodifiableList(new ArrayList<Path>(paths));
            this.truncated = truncated;
        }

        public List<Path> paths() {
            return paths;
        }

        public boolean truncated() {
            return truncated;
        }
    }

    public static final class Path {
        private final CertPath certPath;
        private final TrustAnchor trustAnchor;

        private Path(CertPath certPath, TrustAnchor trustAnchor) {
            this.certPath = certPath;
            this.trustAnchor = trustAnchor;
        }

        public CertPath certPath() {
            return certPath;
        }

        public TrustAnchor trustAnchor() {
            return trustAnchor;
        }

        public X509Certificate issuer() {
            List<? extends Certificate> certificates = certPath.getCertificates();
            if (certificates.size() < 2) {
                return trustAnchor.getTrustedCert();
            }
            Certificate issuer = certificates.get(1);
            return issuer instanceof X509Certificate ? (X509Certificate) issuer : null;
        }
    }

    public static final class Operation implements AutoCloseable {
        private final Scope scope;
        private final int depth;
        private boolean closed;

        private Operation(Scope scope) {
            this.scope = scope;
            depth = scope == null ? 0 : ++scope.operationDepth;
        }

        public void validated(CertPath path, PKIXCertPathValidatorResult result) {
            if (scope == null) {
                return;
            }
            if (closed || CURRENT.get() != scope || scope.operationDepth != depth) {
                throw new IllegalStateException("PKIX observation is outside its operation scope");
            }
            // An inner validator may succeed inside a builder that ultimately rejects.
            if (depth != 1
                    || path == null
                    || path.getCertificates().isEmpty()
                    || !Objects.equals(scope.leaf, path.getCertificates().get(0))) {
                return;
            }
            if (scope.paths.size() == MAX_PATHS) {
                scope.truncated = true;
            } else {
                scope.paths.add(new Path(path, result.getTrustAnchor()));
            }
        }

        @Override
        public void close() {
            if (scope == null) {
                return;
            }
            if (closed || CURRENT.get() != scope || scope.operationDepth != depth) {
                throw new IllegalStateException("PKIX observations must close on their thread in LIFO order");
            }
            closed = true;
            scope.operationDepth--;
        }
    }

    private static final class Scope {
        final X509Certificate leaf;
        final ServerCertificateCheck check;
        final List<Path> paths = new ArrayList<Path>();
        int operationDepth;
        boolean truncated;

        Scope(X509Certificate leaf, ServerCertificateCheck check) {
            this.leaf = leaf;
            this.check = check;
        }

        void forward(Verification verification) throws CertificateException {
            int checkpoint = paths.size();
            boolean previouslyTruncated = truncated;
            boolean succeeded = false;
            try {
                verification.verify();
                succeeded = true;
            } finally {
                if (!succeeded) {
                    // A caught nested rejection must not leave successful inner PKIX paths behind.
                    paths.subList(checkpoint, paths.size()).clear();
                    truncated = previouslyTruncated;
                }
            }
        }
    }
}
