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

package com.netflix.security.provider.certpath;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathChecker;
import java.security.cert.CertPathParameters;
import java.security.cert.PKIXCertPathBuilderResult;

import com.netflix.security.upki.checker.AuthenticatedPaths;
import com.netflix.security.upki.checker.AuthenticatedPaths.Operation;
import com.netflix.security.upki.provider.DelegateFactory;
import com.netflix.security.upki.provider.InvocationGuard;

/** Internal delegated builder with transactional path observation. */
public final class DelegatingCertPathBuilder extends CertPathBuilderSpi {
    private final CertPathBuilder delegate;

    public DelegatingCertPathBuilder(Provider owner, String algorithm) throws NoSuchAlgorithmException {
        delegate = DelegateFactory.create(owner, "CertPathBuilder", algorithm, provider -> CertPathBuilder.getInstance(algorithm, provider));
    }

    @Override
    public CertPathBuilderResult engineBuild(CertPathParameters parameters) throws CertPathBuilderException, InvalidAlgorithmParameterException {
        InvocationGuard guard = InvocationGuard.enter();
        try {
            Operation operation = AuthenticatedPaths.begin();
            try {
                CertPathBuilderResult result = delegate.build(parameters);
                if (result instanceof PKIXCertPathBuilderResult) {
                    PKIXCertPathBuilderResult built = (PKIXCertPathBuilderResult) result;
                    operation.validated(built.getCertPath(), built);
                }
                return result;
            } finally {
                operation.close();
            }
        } finally {
            guard.close();
        }
    }

    @Override
    public CertPathChecker engineGetRevocationChecker() {
        InvocationGuard guard = InvocationGuard.enter();
        try {
            return delegate.getRevocationChecker();
        } finally {
            guard.close();
        }
    }
}
