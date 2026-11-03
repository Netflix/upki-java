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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.netflix.security.provider.UpkiProvider;
import com.netflix.security.upki.RevocationChecker;
import com.netflix.security.upki.RevocationDiagnostics.CacheState;
import com.netflix.security.upki.UpkiConfiguration;
import com.netflix.security.upki.UpkiConfiguration.Builder;
import com.netflix.security.upki.UpkiConfiguration.CacheFailure;
import com.netflix.security.upki.UpkiConfiguration.Handling;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class UpkiProviderTest {
    @TempDir
    Path directory;

    @Test
    void constructionRegistersExactlyTheIntendedServicesButDoesNotInstallOrProbe() throws Exception {
        Files.write(directory.resolve("index.bin"), new byte[0]);
        Provider[] before = Security.getProviders();
        UpkiConfiguration configuration = configuration(directory);
        UpkiProvider provider = new UpkiProvider(configuration);
        assertArrayEquals(before, Security.getProviders());
        assertSame(configuration, provider.configuration());
        assertEquals(UpkiProvider.NAME, provider.getName());
        assertEquals(4, provider.getServices().size());
        for (String type : new String[] {"TrustManagerFactory", "CertPathValidator", "CertPathBuilder"}) {
            assertSame(provider, provider.getService(type, "PKIX").getProvider());
        }
        assertSame(provider, provider.getService("TrustManagerFactory", "UPKI")
                .getProvider());
        assertNull(provider.getService("CertPathValidator", "UPKI"));
        assertEquals(0, provider.diagnostics().assessments());
        assertEquals(CacheState.NOT_CHECKED, provider.diagnostics().cacheState());
    }

    @Test
    void equivalentConfigurationHasValueEqualityWithoutNormalizingOrProbingPaths() {
        UpkiConfiguration a = configuration(directory);
        UpkiConfiguration b = configuration(directory);
        assertNotSame(a, b);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertEquals(a, a);
        assertNotEquals(a, null);
        assertNotEquals(a, new Object());
        List<UpkiConfiguration> different = new ArrayList<>();
        different.add(builder(directory.resolve("other")).build());
        different.add(builder(directory)
                .automaticDiscovery()
                .build());
        different.add(builder(directory)
                .enabled(false)
                .build());
        different.add(builder(directory)
                .missingIndex(Handling.FAIL)
                .build());
        different.add(builder(directory)
                .cacheFailure(CacheFailure.FAIL_CLOSED)
                .build());
        different.add(builder(directory)
                .missingScts(Handling.FAIL)
                .build());
        different.add(builder(directory)
                .coverage(Handling.FAIL)
                .build());
        different.add(builder(directory)
                .unsupportedVerification(Handling.FAIL)
                .build());
        different.add(builder(directory.resolve("child/..")).build());
        for (UpkiConfiguration other : different) {
            assertNotEquals(a, other);
            assertNotEquals(other, a);
        }
    }

    @Test
    void nullConfigurationDoesNotChangeProviderRegistration() {
        Provider[] before = Security.getProviders();
        assertThrows(NullPointerException.class, () -> new UpkiProvider(null));
        assertThrows(NullPointerException.class, () -> UpkiProvider.install(null));
        assertArrayEquals(before, Security.getProviders());
    }

    @Test
    void liveProviderCannotBeClonedOrSerializedIntoAnInvalidOwner() throws Exception {
        UpkiProvider provider = new UpkiProvider(configuration(directory));
        assertThrows(UnsupportedOperationException.class, provider::clone);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (ObjectOutputStream stream = new ObjectOutputStream(output)) {
            NotSerializableException rejection = assertThrows(NotSerializableException.class, () -> stream.writeObject(provider));
            assertTrue(rejection.getMessage().contains(UpkiProvider.class.getName()));
        }
        assertEquals(4, provider.getServices().size());
    }

    @Test
    void deserializationCannotBypassExplicitProviderConstruction() throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (ObjectOutputStream stream = new ObjectOutputStream(output)) {
            stream.writeObject(new SerializedProvider());
        }
        try (ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(output.toByteArray())) {
            @Override
            protected ObjectStreamClass readClassDescriptor() throws IOException, ClassNotFoundException {
                ObjectStreamClass descriptor = super.readClassDescriptor();
                return descriptor.getName().equals(SerializedProvider.class.getName()) ? ObjectStreamClass.lookup(UpkiProvider.class) : descriptor;
            }
        }) {
            InvalidObjectException rejection = assertThrows(InvalidObjectException.class, stream::readObject);
            assertTrue(rejection.getMessage().contains("explicit construction"));
        }
    }

    private static final class SerializedProvider extends Provider {
        private static final long serialVersionUID = 1L;

        @SuppressWarnings("deprecation")
        SerializedProvider() {
            super("UPKI-serialization-test", 1.0, "Test-only stream descriptor");
        }
    }

    @Test
    void routingHelpersAreAbsentFromTheExportedProviderPackage() {
        for (String name : new String[] {"DelegateFactory", "DelegatingService", "InvocationGuard"}) {
            assertThrows(ClassNotFoundException.class,
                    () -> Class.forName("com.netflix.security.provider." + name, false, UpkiProvider.class.getClassLoader()));
        }
    }

    @Test
    void providerExportDoesNotExportRoutingOrSpiImplementationPackages() {
        Module module = UpkiProvider.class.getModule();
        assertSame(RevocationChecker.class.getModule(), module);
        assertTrue(module.isExported("com.netflix.security.provider"));
        assertTrue(
                module.getDescriptor()
                      .provides()
                      .stream()
                      .anyMatch(service ->
                              service.service().equals(Provider.class.getName()) && service.providers().equals(Arrays.asList(UpkiProvider.class.getName()))));
        assertFalse(module.isExported("com.netflix.security.upki.provider"));
        assertFalse(module.isExported("com.netflix.security.ssl"));
        assertFalse(module.isExported("com.netflix.security.provider.certpath"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"install", "https", "https-closed", "https-missing-ignore", "https-missing-fail", "https-disabled",
                "delegation", "late", "layering"})
    void actualProviderInAnIsolatedJvm(String scenario) throws Exception {
        String executable = System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java";
        Path java = Paths.get(System.getProperty("java.home"), "bin", executable);
        Set<String> locations = probeLocations();
        Path output = directory.resolve(scenario + ".log");
        Process process = new ProcessBuilder(java.toString(), "-cp", String.join(File.pathSeparator, locations), UpkiProviderProbe.class.getName(), scenario)
                .redirectErrorStream(true)
                .redirectOutput(output.toFile())
                .start();
        if (!process.waitFor(45, TimeUnit.SECONDS)) {
            process.destroyForcibly().waitFor();
            fail("Provider probe timed out: " + output);
        }
        String report = new String(Files.readAllBytes(output), StandardCharsets.UTF_8);
        assertEquals(0, process.exitValue(), report);
        assertTrue(report.contains("PASS provider " + scenario), report);
    }

    static Set<String> probeLocations() throws Exception {
        Set<String> locations = new LinkedHashSet<>();
        for (String name : Arrays.asList(
                UpkiProvider.class.getName(),
                UpkiProviderProbe.class.getName(),
                ProviderTlsFixture.class.getName(),
                CertificateFixture.class.getName(),
                CacheFixture.class.getName(),
                "com.netflix.security.upki.RevocationDiagnostics",
                "com.netflix.security.upki.RevocationResult",
                "com.netflix.security.upki.UpkiConfiguration",
                "com.netflix.security.upki.UpkiAgent",
                "com.netflix.security.upki.provider.ProviderConfiguration",
                "com.netflix.security.upki.provider.DelegateFactory",
                "com.netflix.security.upki.provider.DelegatingService",
                "com.netflix.security.upki.provider.InvocationGuard",
                "com.netflix.security.upki.checker.ConfiguredChecks",
                "com.netflix.security.upki.checker.AuthenticatedPaths",
                "com.netflix.security.upki.checker.ServerCertificateCheck",
                "com.netflix.security.upki.checker.CacheChecker",
                "com.netflix.security.upki.checker.CheckPolicy",
                "com.netflix.security.upki.checker.CheckDiagnostics",
                "com.netflix.security.upki.checker.RevocationEnforcer",
                "com.netflix.security.upki.checker.CertificateInputs",
                "com.netflix.security.upki.checker.RevocationInput",
                "com.netflix.security.upki.cache.CacheDiscovery",
                "com.netflix.security.upki.cache.CachePaths",
                "com.netflix.security.upki.cache.RevocationIndex",
                "com.netflix.security.upki.clubcard.Clubcard",
                "com.netflix.security.upki.clubcard.ClubcardReader",
                "com.netflix.security.ssl.ServerTrustManager",
                "com.netflix.security.ssl.DelegatingTrustManagerFactory",
                "com.netflix.security.provider.certpath.DelegatingCertPathValidator",
                "com.netflix.security.provider.certpath.DelegatingCertPathBuilder")) {
            for (Class<?> type : Class.forName(name).getNestMembers()) {
                locations.add(Paths.get(type.getProtectionDomain()
                                            .getCodeSource()
                                            .getLocation()
                                            .toURI())
                        .toString());
            }
        }
        return locations;
    }

    static UpkiConfiguration configuration(Path directory) {
        return builder(directory).build();
    }

    private static Builder builder(Path directory) {
        return UpkiConfiguration.builder()
                .cacheDirectory(directory)
                .enabled(true)
                .missingIndex(Handling.WARN)
                .cacheFailure(CacheFailure.FAIL_OPEN)
                .missingScts(Handling.IGNORE)
                .coverage(Handling.IGNORE)
                .unsupportedVerification(Handling.WARN);
    }
}
