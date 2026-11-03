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

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.util.Collections;

import com.netflix.security.upki.RevocationChecker;
import com.netflix.security.upki.RevocationDiagnostics.CacheState;
import com.netflix.security.upki.RevocationResult;
import com.netflix.security.upki.RevocationResult.Finding;
import com.netflix.security.upki.RevocationResult.Operation;
import com.netflix.security.upki.UpkiConfiguration;
import com.netflix.security.upki.UpkiConfiguration.CacheFailure;
import com.netflix.security.upki.UpkiConfiguration.Handling;

/**
 * Java 8-compatible consumer using only the public library API and
 * project-authored fixtures.
 */
public final class PublicApiProbe {
    public static void main(String[] args) throws Exception {
        CertificateFixture issuer = new CertificateFixture(new byte[] {110}, false, true, null);
        byte[] scts = CertificateFixture.list(CertificateFixture.sct(1, 150, new byte[0], new byte[] {1}));
        CertificateFixture leaf = new CertificateFixture(new byte[] {111}, true, true, scts, issuer.keys,
                "CN=localhost");
        CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(Collections.singletonList(leaf.certificate));
        PKIXParameters parameters = new PKIXParameters(Collections.singleton(new TrustAnchor(issuer.certificate, null)));
        parameters.setRevocationEnabled(false);
        CertPathValidator.getInstance("PKIX").validate(path, parameters);
        Path directory = Files.createTempDirectory("upki-public-api-");
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(issuer.spki);
            CacheFixture.write(directory, hash, false);
            RevocationChecker checker = checker(directory, true, Handling.FAIL, CacheFailure.FAIL_CLOSED);
            require(checker.diagnostics().assessments() == 0, "construction probed the cache");
            require(checker.check(leaf.certificate, issuer.certificate).finding() == Finding.NOT_REVOKED, "not-revoked lookup");
            CacheFixture.write(directory, hash, true);
            require(checker.check(leaf.certificate, issuer.certificate).finding() == Finding.REVOKED, "revocation lookup");
            require(checker.diagnostics().policyRejected() == 1, "revocation not diagnosed");
            require(checker.diagnostics().cacheState() == CacheState.USABLE, "revocation is not broken infrastructure");
            Files.write(directory.resolve("index.bin"), new byte[0]);
            RevocationResult broken = checker.check(leaf.certificate, issuer.certificate);
            require(broken.finding() == Finding.FAILED && broken.failures().size() == 1, "failure lost");
            require(broken.failures()
                          .get(0)
                          .operation()
                    == Operation.INDEX_OPEN,
                    "wrong failure operation");
            require(checker.diagnostics().policyRejected() == 2, "strict cache decision not diagnosed");
            RevocationChecker open = checker(directory, true, Handling.IGNORE, CacheFailure.FAIL_OPEN);
            require(open.check(leaf.certificate, issuer.certificate).finding() == Finding.FAILED, "fail-open erased failure");
            require(open.diagnostics().cacheFailOpen() == 1, "fail-open not diagnosed");
            Files.delete(directory.resolve("index.bin"));
            for (Handling handling : Handling.values()) {
                RevocationChecker missing = checker(directory, true, handling, CacheFailure.FAIL_CLOSED);
                require(missing.check(leaf.certificate, issuer.certificate).finding() == Finding.NO_DATA, "missing index");
                require(missing.diagnostics().degraded() == (handling != Handling.IGNORE), "missing-index severity");
                require(missing.diagnostics().policyRejected() == (handling == Handling.FAIL ? 1 : 0), "missing-index decision");
            }
            CertificateFixture malformed = new CertificateFixture(new byte[] {112}, true, true,
                    new byte[] {0, 0}, issuer.keys, "CN=localhost");
            RevocationChecker disabled = checker(directory, false, Handling.FAIL, CacheFailure.FAIL_CLOSED);
            require(disabled.check(malformed.certificate, issuer.certificate).finding() == Finding.DISABLED, "disabled input decode");
            System.out.println("PASS public API java=" + System.getProperty("java.version"));
        } finally {
            Files.deleteIfExists(directory.resolve("index.bin"));
            Files.deleteIfExists(directory.resolve("test.filter"));
            Files.delete(directory);
        }
    }

    private static RevocationChecker checker(Path directory, boolean enabled, Handling missingIndex,
            CacheFailure cacheFailure) {
        return new RevocationChecker(
                UpkiConfiguration.builder()
                        .cacheDirectory(directory)
                        .enabled(enabled)
                        .missingIndex(missingIndex)
                        .cacheFailure(cacheFailure)
                        .missingScts(Handling.IGNORE)
                        .coverage(Handling.IGNORE)
                        .unsupportedVerification(Handling.WARN)
                        .build());
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
