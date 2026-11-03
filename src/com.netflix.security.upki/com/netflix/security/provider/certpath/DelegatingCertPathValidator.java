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
import java.security.cert.CertPath;
import java.security.cert.CertPathChecker;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.PKIXCertPathValidatorResult;

import com.netflix.security.upki.checker.AuthenticatedPaths;
import com.netflix.security.upki.checker.AuthenticatedPaths.Operation;
import com.netflix.security.upki.provider.DelegateFactory;
import com.netflix.security.upki.provider.InvocationGuard;

/** Internal delegated validator with transactional path observation. */
public final class DelegatingCertPathValidator extends CertPathValidatorSpi {
    private final CertPathValidator delegate;

    public DelegatingCertPathValidator(Provider owner, String algorithm) throws NoSuchAlgorithmException {
        delegate = DelegateFactory.create(owner, "CertPathValidator", algorithm, provider -> CertPathValidator.getInstance(algorithm, provider));
    }

    @Override
    public CertPathValidatorResult engineValidate(CertPath path, CertPathParameters parameters) throws CertPathValidatorException, InvalidAlgorithmParameterException {
        InvocationGuard guard = InvocationGuard.enter();
        try {
            Operation operation = AuthenticatedPaths.begin();
            try {
                CertPathValidatorResult result = delegate.validate(path, parameters);
                if (result instanceof PKIXCertPathValidatorResult) {
                    operation.validated(path, (PKIXCertPathValidatorResult) result);
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
