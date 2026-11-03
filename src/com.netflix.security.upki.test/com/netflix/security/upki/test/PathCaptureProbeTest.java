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

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.List;
import javax.tools.ToolProvider;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Forked probes keep experimental global PKIX provider registration out of the
 * test JVM.
 */
class PathCaptureProbeTest {
    private static final String MAIN = "com.netflix.security.upki.test.fixture.PathCaptureProbe";

    @TempDir
    static Path directory;

    private static Path classes;
    private static Path runtime;

    @BeforeAll
    static void prepare() throws Exception {
        String configured = System.getenv("UPKI_TEST_JAVA_HOME");
        runtime = Paths.get(configured == null ? System.getProperty("java.home") : configured);
        classes = Files.createDirectory(directory.resolve("classes"));
        Path source = directory.resolve("PathCaptureProbe.java");
        try (InputStream input = PathCaptureProbeTest.class.getResourceAsStream("fixture/PathCaptureProbe.java.txt")) {
            assertNotNull(input);
            Files.copy(input, source);
        }
        assertEquals(
                0,
                ToolProvider.getSystemJavaCompiler().run(null, null, null, "--release", "8", "-d",
                        classes.toString(), source.toString()));

        CertificateFixture issuerA = new CertificateFixture(new byte[] {11}, false, true, null);
        CertificateFixture issuerB = new CertificateFixture(new byte[] {12}, false, true, null);
        CertificateFixture decoy = new CertificateFixture(new byte[] {13}, true, true, null);
        CertificateFixture unrelated = new CertificateFixture(new byte[] {14}, true, true, null, null,
                "CN=unrelated");
        CertificateFixture leafA = new CertificateFixture(new byte[] {15}, true, true, null, issuerA.keys,
                "CN=localhost");
        CertificateFixture leafB = new CertificateFixture(new byte[] {16}, true, true, null, issuerB.keys,
                "CN=second");
        CertificateFixture intermediate = CertificateFixture.authority(new byte[] {18}, issuerA, "CN=intermediate");
        CertificateFixture intermediateLeaf = CertificateFixture.issued(new byte[] {19}, intermediate, "CN=localhost");
        List<CertificateFixture> fixtures = Arrays.asList(issuerA, issuerB, decoy, unrelated, leafA, leafB,
                intermediate, intermediateLeaf);
        List<String> names = Arrays.asList("issuer-a", "issuer-b", "decoy", "unrelated", "leaf-a", "leaf-b",
                "intermediate", "leaf-intermediate");
        for (int i = 0; i < fixtures.size(); i++) {
            Files.write(directory.resolve(names.get(i) + ".der"),
                    fixtures.get(i).certificate.getEncoded());
        }
        CertificateFixture variant = new CertificateFixture(new byte[] {17}, false, false, null, issuerA.keys,
                "CN=upki-java test issuer", issuerA.keys);
        byte[] forged = variant.certificate.getEncoded();
        forged[forged.length - 1] ^= 1;
        Files.write(directory.resolve("variant.der"), forged);
        Files.write(directory.resolve("issuer-a.spki"), issuerA.spki);
        Files.write(directory.resolve("variant.spki"), variant.spki);
        KeyStore roots = KeyStore.getInstance("JKS");
        roots.load(null, null);
        roots.setCertificateEntry("issuer-a", issuerA.certificate);
        roots.setCertificateEntry("issuer-b", issuerB.certificate);
        try (OutputStream output = Files.newOutputStream(directory.resolve("roots.jks"))) {
            roots.store(output, "changeit".toCharArray());
        }
        KeyStore identity = KeyStore.getInstance("JKS");
        identity.load(null, null);
        identity.setKeyEntry("server", leafA.keys.getPrivate(), "changeit".toCharArray(),
                new Certificate[] {leafA.certificate, issuerA.certificate});
        try (OutputStream output = Files.newOutputStream(directory.resolve("server.jks"))) {
            identity.store(output, "changeit".toCharArray());
        }
        identity.setKeyEntry("server", intermediateLeaf.keys.getPrivate(), "changeit".toCharArray(),
                new Certificate[] {intermediateLeaf.certificate, intermediate.certificate, issuerA.certificate});
        try (OutputStream output = Files.newOutputStream(directory.resolve("intermediate-server.jks"))) {
            identity.store(output, "changeit".toCharArray());
        }
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(
            strings = {
                "ordered",
                "unordered",
                "omitted",
                "opaque",
                "default-store",
                "parameters",
                "post-validation-reject",
                "checker-reject",
                "concurrent",
                "nested",
                "sunx509",
                "pinned",
                "direct-trust",
                "key-only-anchor",
                "tls",
                "tls-hostname-reject",
                "delegation-api",
                "spki-ambiguity",
                "multiple-paths",
                "nested-builder-reject",
                "opaque-indistinguishable",
                "cached-validator",
                "intermediate",
                "hidden-intermediate",
                "tls-intermediate",
                "off-thread",
                "different-leaf"
            })
    void observesOnlySuccessfulDelegatedPathsWithinTheCurrentCheck(String scenario) throws Exception {
        Path output = directory.resolve(scenario + ".log");
        String executable = System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java";
        Process process = new ProcessBuilder(
                runtime.resolve("bin")
                       .resolve(executable)
                       .toString(),
                "-cp",
                classes.toString(),
                MAIN,
                directory.toString(),
                scenario)
                .redirectErrorStream(true)
                .redirectOutput(output.toFile())
                .start();
        if (!process.waitFor(30, SECONDS)) {
            process.destroyForcibly();
            fail("Probe timed out: " + output);
        }
        String report = new String(Files.readAllBytes(output), StandardCharsets.UTF_8);
        assertEquals(0, process.exitValue(), report);
        assertTrue(report.contains("PASS " + scenario), report);
    }
}
