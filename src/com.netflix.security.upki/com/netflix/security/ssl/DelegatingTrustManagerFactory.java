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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;

import com.netflix.security.upki.checker.ServerCertificateCheck;
import com.netflix.security.upki.provider.DelegateFactory;
import com.netflix.security.upki.provider.InvocationGuard;

/**
 * Internal factory adapter; server enforcement is supplied by internal
 * integration code.
 */
public final class DelegatingTrustManagerFactory extends TrustManagerFactorySpi {
    private final TrustManagerFactory delegate;
    private final ServerCertificateCheck serverCheck;

    public DelegatingTrustManagerFactory(Provider owner, String algorithm) throws NoSuchAlgorithmException {
        this(owner, algorithm, null);
    }

    public DelegatingTrustManagerFactory(Provider owner, String algorithm, ServerCertificateCheck serverCheck) throws NoSuchAlgorithmException {
        delegate = DelegateFactory.create(owner, "TrustManagerFactory", algorithm, provider -> TrustManagerFactory.getInstance(algorithm, provider));
        this.serverCheck = serverCheck;
    }

    @Override
    protected void engineInit(KeyStore store) throws KeyStoreException {
        InvocationGuard guard = InvocationGuard.enter();
        try {
            delegate.init(store);
        } finally {
            guard.close();
        }
    }

    @Override
    protected void engineInit(ManagerFactoryParameters parameters) throws InvalidAlgorithmParameterException {
        InvocationGuard guard = InvocationGuard.enter();
        try {
            delegate.init(parameters);
        } finally {
            guard.close();
        }
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        InvocationGuard guard = InvocationGuard.enter();
        try {
            TrustManager[] managers = delegate.getTrustManagers();
            if (serverCheck == null) {
                return managers;
            }
            TrustManager[] wrapped = managers.clone();
            for (int i = 0; i < wrapped.length; i++) {
                wrapped[i] = ServerTrustManager.wrap(wrapped[i], serverCheck);
            }
            return wrapped;
        } finally {
            guard.close();
        }
    }
}
