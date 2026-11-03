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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import com.netflix.security.upki.checker.AuthenticatedPaths.Result;

/**
 * Internal enforcement seam, not an application callback or diagnostic listener
 * API.
 */
@FunctionalInterface
public interface ServerCertificateCheck {
    void check(X509Certificate leaf, Result evidence) throws CertificateException;
}
